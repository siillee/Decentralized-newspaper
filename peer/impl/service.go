package impl

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"

	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/registry"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

// Start implements peer.Service
func (n *node) Start() error {
	n.setOpen(true)
	// z.Logger.Info().Msgf("[%s] Starting peer", n.GetAddress())

	n.RegisterHandlers()

	go func() {
		n.Listen()
		// z.Logger.Info().Msgf("[%s] done with listening to you guys", n.GetAddress())
	}()

	go n.antiEntropyMechanism()

	go n.heartbeatMechanism()

	go n.runProofMaintenance()

	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// z.Logger.Info().Msgf("[%s] Stopping peer", n.GetAddress())
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
		types.ArticleSummaryMessage{},
		types.CommentMessage{},
		types.VoteMessage{},
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
		n.ExecArticleSummaryMessage,
		n.ExecCommentMessage,
		n.ExecVoteMessage,
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

		// z.Logger.Info().Msgf("[%s] LIVE finna try and receive a packet", n.GetAddress())
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
	// z.Logger.Info().Msgf("[%s] there's a packet here...", n.GetAddress())
	if dest == n.GetAddress() {
		// z.Logger.Info().Msgf("[%s] LIVE finna process this packet", n.GetAddress())
		err := n.conf.MessageRegistry.ProcessPacket(pkt)
		// z.Logger.Info().Msgf("[%s] LIVE exited ProcessPacket", n.GetAddress())
		return err
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
			// z.Logger.Debug().Msgf("[%s] no neighbor found (anti-entropy mechanism)", n.GetAddress())
		} else {
			statusTransportMessage, err := types.ToTransport(n.view.Copy())
			if err != nil {
				z.Logger.Err(err).Msgf("[%s] failed to build status transport message", n.GetAddress())
			}

			_, err = n.SendTo(neighbor, statusTransportMessage)
			// z.Logger.Debug().Msgf("[%s] send status message to %s (anti-entropy mechanism)", n.GetAddress(), neighbor)
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
		// z.Logger.Debug().Msgf("[%s] send empty message (heartbeat mechanism)", n.GetAddress())
		if err != nil {
			z.Logger.Err(err).Msgf("[%s] failed to broadcast empty message (hearthbeat mechansim)", n.GetAddress())
		}

		time.Sleep(n.conf.HeartbeatInterval)
	}
}

// Updates the proof store periodically, providing values for proof of work (used in the VoteMessage to restrict the number of sybil identities)
func (n *node) runProofMaintenance() {
	keysRaw := []rsa.PublicKey{
		n.recommender.key.PublicKey,
	}

	// Translate the keys to strings as we only need their values (not cryptographic utility), and strings are easier to work with
	keys := make([]string, 0)
	for _, raw := range keysRaw {
		bytes := x509.MarshalPKCS1PublicKey(&raw)

		key := string(bytes)
		keys = append(keys, key)
	}

	// Periodically check if any proof needs to be calculated
	// Happens only at the start of the week or node setup, the check isn't complex, so checking from time to time isn't bad
	for {
		if !n.isOpen() {
			return
		}

		n.proofMaintenanceLoop(keys)

		time.Sleep(1 * time.Hour)
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
