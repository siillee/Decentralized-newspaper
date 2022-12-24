package impl

import (
	"errors"
	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/registry"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"time"
)

// Start implements peer.Service
func (n *node) Start() error {
	n.setOpen(true)
	z.Logger.Info().Msgf("[%s] Starting peer", n.GetAddress())

	n.RegisterHandlers()

	go n.Listen()

	go n.antiEntropyMechanism()

	go n.heartbeatMechanism()

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	z.Logger.Info().Msgf("[%s] Stopping peer", n.GetAddress())
	if !n.isOpen() {
		return xerrors.Errorf("peer %s is already closed", n.GetAddress())
	}
	n.setOpen(false)
	return nil
}

func (n *node) RegisterHandlers() {
	handledTypes := []types.Message{
		types.ChatMessage{},
		types.RumorsMessage{},
		types.AckMessage{},
		types.StatusMessage{},
		types.EmptyMessage{},
		types.PrivateMessage{},
		types.DataRequestMessage{},
		types.DataReplyMessage{},
		types.SearchRequestMessage{},
		types.SearchReplyMessage{},
	}
	handlers := []registry.Exec{
		n.ExecChatMessage,
		n.ExecRumorsMessage,
		n.ExecAckMessage,
		n.ExecStatusMessage,
		n.ExecEmptyMessage,
		n.ExecPrivateMessage,
		n.ExecDataRequestMessage,
		n.ExecDataReplyMessage,
		n.ExecSearchRequestMessage,
		n.ExecSearchReplyMessage,
	}
	for i, msgType := range handledTypes {
		n.conf.MessageRegistry.RegisterMessageCallback(msgType, handlers[i])
	}
}

func (n *node) Listen() {
	for {
		if !n.isOpen() {
			return
		}

		pkt, err := n.conf.Socket.Recv(time.Second * 1)
		if err != nil {
			if errors.Is(err, transport.TimeoutError(0)) {
				continue
			} else {
				z.Logger.Err(err).Msgf("[%s] Error while receiving packet", n.GetAddress())
			}
		}

		err = n.HandlePacket(pkt)
		if err != nil {
			z.Logger.Err(err).Msgf("[%s] Error during handling packet of type %s", n.GetAddress(), pkt.Msg.Type)
		}
	}
}

func (n *node) HandlePacket(pkt transport.Packet) error {
	dest := pkt.Header.Destination
	if dest == n.GetAddress() {
		return n.conf.MessageRegistry.ProcessPacket(pkt)
	}

	//relay packet
	pkt.Header.RelayedBy = n.GetAddress()
	to, ok := n.routingTable.GetEntry(dest)
	if !ok {
		return xerrors.Errorf("unable to relay packet to %s (unknown destination)", dest)
	}
	return n.conf.Socket.Send(to, pkt, 0)
}

func (n *node) antiEntropyMechanism() {
	if n.conf.AntiEntropyInterval == 0 {
		return
	}
	for {
		if !n.isOpen() {
			return
		}

		neighbor := n.GetRandomNeighbor("")
		if neighbor == "" {
			z.Logger.Debug().Msgf("[%s] no neighbor found (anti-entropy mechanism)", n.GetAddress())
		} else {
			statusTransportMessage, err := types.ToTransport(n.view.Copy())
			if err != nil {
				z.Logger.Err(err).Msgf("[%s] failed to build status transport message", n.GetAddress())
			}

			_, err = n.SendTo(neighbor, statusTransportMessage)
			z.Logger.Debug().Msgf("[%s] send status message to %s (anti-entropy mechanism)", n.GetAddress(), neighbor)
			if err != nil {
				z.Logger.Err(err).Msgf("[%s] failed to send status message to %s", n.GetAddress(), neighbor)
			}
		}

		time.Sleep(n.conf.AntiEntropyInterval)
	}
}

func (n *node) heartbeatMechanism() {
	if n.conf.HeartbeatInterval == 0 {
		return
	}
	for {
		if !n.isOpen() {
			return
		}

		emptyTransportMessage, err := types.ToTransport(types.EmptyMessage{})
		if err != nil {
			z.Logger.Err(err).Msgf("[%s] failed to build empty transport message", n.GetAddress())
		}

		err = n.Broadcast(emptyTransportMessage)
		z.Logger.Debug().Msgf("[%s] send empty message (heartbeat mechanism)", n.GetAddress())
		if err != nil {
			z.Logger.Err(err).Msgf("[%s] failed to broadcast empty message (hearthbeat mechansim)", n.GetAddress())
		}

		time.Sleep(n.conf.HeartbeatInterval)
	}
}

func (n *node) isOpen() bool {
	n.Lock()
	defer n.Unlock()
	return n.open
}

func (n *node) setOpen(val bool) {
	n.Lock()
	defer n.Unlock()
	n.open = val
}
