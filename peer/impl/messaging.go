package impl

import (
	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"time"
)

func (n *node) SendTo(dest string, msg transport.Message) (transport.Packet, error) {
	header := transport.NewHeader(
		n.GetAddress(), // source
		n.GetAddress(), // relay
		dest,           // destination
		0,              // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	return pkt, n.conf.Socket.Send(dest, pkt, 0)
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	to, ok := n.routingTable.GetEntry(dest)
	if !ok {
		return xerrors.Errorf("%s can't reach %s", n.GetAddress(), dest)
	}

	header := transport.NewHeader(
		n.GetAddress(), // source
		n.GetAddress(), // relay
		dest,           // destination
		0,              // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}
	err := n.conf.Socket.Send(to, pkt, 0)
	z.Logger.Info().Msgf("[%s] unicast message to %s via %s", n.GetAddress(), dest, to)
	if err != nil {
		return xerrors.Errorf("failed to send packet to %s: %v", to, err)
	}

	return nil
}

func (n *node) Broadcast(msg transport.Message) error {

	// Process pkt locally
	localHeader := transport.NewHeader(n.GetAddress(), n.GetAddress(), n.GetAddress(), 0)
	localPkt := transport.Packet{Header: &localHeader, Msg: &msg}
	err := n.conf.MessageRegistry.ProcessPacket(localPkt)
	if err != nil {
		z.Logger.Err(err).Msgf("[%s] error while processing local packet during broadcast", n.GetAddress())
		return err
	}

	// Build rumor
	rumorsTransportMessage, err := types.ToTransport(n.CreateRumor(msg))
	if err != nil {
		z.Logger.Err(err).Msgf("[%s] failed to build rumors transport message", n.GetAddress())
		return err
	}

	// Send rumor to a random neighbor
	neighbor := n.GetRandomNeighbor("")
	if neighbor == "" {
		z.Logger.Debug().Msgf("[%s] unable to broadcast rumor (no neighbor found)", n.GetAddress())
		return nil
	}
	pkt, err := n.SendTo(neighbor, rumorsTransportMessage)
	z.Logger.Info().Msgf("[%s] broadcast rumor to %s", n.GetAddress(), neighbor)
	if err != nil {
		z.Logger.Err(err).Msgf("[%s] failed to broadcast to %s", n.GetAddress(), neighbor)
		return err
	}

	// Waiting for ack (only loop if AckTimeout > 0)
	go n.WaitForAck(pkt, neighbor, rumorsTransportMessage)

	return nil
}

func (n *node) WaitForAck(pkt transport.Packet, from string, rumorsTransportMessage transport.Message) {
	if n.conf.AckTimeout == 0 {
		return
	}

	n.ackChannels.Add(pkt.Header.PacketID, make(chan bool))
	defer n.ackChannels.Del(pkt.Header.PacketID)

	for {
		select {
		case <-n.ackChannels.Get(pkt.Header.PacketID):
			z.Logger.Debug().Msgf("[%s] ack received, stop timeout", n.GetAddress())
			return
		case <-time.After(n.conf.AckTimeout):
			// Send rumor to another random neighbor
			neighbor := n.GetRandomNeighbor(from)
			z.Logger.Debug().Msgf("[%s] ack timeout, sending to another random neighbor: %s", n.GetAddress(), neighbor)

			_, err := n.SendTo(neighbor, rumorsTransportMessage)
			if err != nil {
				z.Logger.Err(err).Msgf("[%s] failed to broadcast to another random neighbor %s", n.GetAddress(), neighbor)
			}

			return
		}
	}
}

func (n *node) CreateRumor(msg transport.Message) types.RumorsMessage {
	n.Lock()
	n.currentSequenceNumber++
	currentSeq := n.currentSequenceNumber
	n.Unlock()

	rumor := types.Rumor{
		Origin:   n.GetAddress(),
		Sequence: currentSeq,
		Msg:      &msg,
	}

	n.view.Set(n.GetAddress(), currentSeq)
	n.rumorsStore.Add(n.GetAddress(), rumor)
	rumors := []types.Rumor{rumor}
	return types.RumorsMessage{Rumors: rumors}
}

func (n *node) GetAddress() string {
	return n.conf.Socket.GetAddress()
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	for _, entry := range addr {
		z.Logger.Info().Msgf("[%s] add peer %s", n.GetAddress(), entry)
		n.routingTable.AddEntry(entry, entry)
	}
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	copyTable := make(peer.RoutingTable)
	for key, value := range n.routingTable.GetEntries() {
		copyTable[key] = value
	}
	return copyTable
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	z.Logger.Debug().Msgf("[%s] set routing entry : %s -> %s", n.GetAddress(), origin, relayAddr)
	if !(origin == n.GetAddress() && relayAddr == "") {
		n.routingTable.AddEntry(origin, relayAddr)
	}
}
