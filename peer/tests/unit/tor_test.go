package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/udp"
)

// Tests the connection of a new node to the directory servers.
func Test_Tor_Directory_Fill(t *testing.T) {

	udp := udp.NewUDP()

	directoryNode1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2000")
	defer directoryNode1.Stop()

	directoryNode2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2001")
	defer directoryNode2.Stop()

	directoryNode3 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2002")
	defer directoryNode3.Stop()

	directoryNode4 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2003")
	defer directoryNode4.Stop()

	directoryNode5 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2004")
	defer directoryNode5.Stop()

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0")
	defer node1.Stop()

	time.Sleep(time.Millisecond * 300)
	dir := node1.GetDirectory()
	require.Len(t, dir, 5)
}
