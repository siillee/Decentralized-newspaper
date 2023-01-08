package unit

import (
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
)

// Tests the connection of a new node to the directory servers.
func Test_Tor_Directory_Fill(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryServers(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0")
	defer node1.Stop()

	time.Sleep(time.Millisecond * 300)
	dir := node1.GetDirectory()
	require.Len(t, dir, 5)
}

func Test_Tor_Circuit_Create(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryServers(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0")
	defer node1.Stop()
	time.Sleep(time.Millisecond * 300)

	circuit, err := node1.CreateRandomCircuit()
	require.NoError(t, err)
	require.Len(t, circuit.AllSharedKeys, 3)
}

func Test_Tor_Anonymous_Broadcast(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryServers(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0")
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0")
	defer node1.Stop()
	time.Sleep(time.Millisecond * 300)

	node1.SendAnonymousArticleSummaryMessage(types.ArticleSummaryMessage{
		ArticleID: xid.New().String(),
		Title:     "LoremIpsum",
	})
	// Enough time for the message to reach node2.
	time.Sleep(time.Second * 1)

	ins2 := node2.GetIns()
	var address string
	for _, x := range ins2 {
		if x.Msg.Type == (types.ArticleSummaryMessage{}).Name() {
			address = x.Header.Source
			break
		}
	}

	require.NotEqual(t, node1.GetAddr(), address)
}

//----------------------------------Helper functions---------------------------------------------

func startDirectoryServers(udp transport.Transport, t *testing.T) []peer.Peer {

	directoryNode1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2000")
	directoryNode2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2001")
	directoryNode3 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2002")
	directoryNode4 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2003")
	directoryNode5 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2004")
	directoryNode6 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2005")
	directoryNode7 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2006")
	directoryNode8 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2007")
	directoryNode9 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2008")
	directoryNode10 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2009")

	return []peer.Peer{directoryNode1, directoryNode2, directoryNode3, directoryNode4, directoryNode5,
		directoryNode6, directoryNode7, directoryNode8, directoryNode9, directoryNode10}

}
