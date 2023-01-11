package unit

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
)

// Tests the connection of a new node to the directory servers.
func Test_Tor_Directory_Fill(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryNodes(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node1.Stop()

	time.Sleep(time.Second * 2)
	dir := node1.GetDirectory()
	require.Len(t, dir, 10)
}

func Test_Tor_Circuit_Create(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryNodes(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node1.Stop()
	time.Sleep(time.Second * 2)

	circuit, err := node1.CreateRandomCircuit()
	require.NoError(t, err)
	require.Len(t, circuit.AllSharedKeys, 3)
}

func Test_Tor_Anonymous_Broadcast(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryNodes(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node2.Stop()
	time.Sleep(time.Second * 2)

	title := "LoremIpsum"
	content := " Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam varius maximus tellus, vel congue nunc" +
		" efficitur a. Duis vel sagittis lacus, a vulputate massa. Maecenas molestie tempor felis sit amet sodales. " +
		"Pellentesque porttitor convallis neque, iaculis maximus quam scelerisque blandit. Maecenas euismod nibh mi, " +
		"vel egestas mi vulputate ut. Mauris iaculis mattis est sed sodales. Mauris hendrerit malesuada lectus ut " +
		"dictum.\n\nDonec ornare lectus nec nunc maximus, at posuere ante posuere. Quisque finibus ex facilisis, " +
		"tristique elit eu, pulvinar ex. Curabitur accumsan at ex quis condimentum. Pellentesque mi nulla, tempor " +
		"posuere tellus fermentum, porta ullamcorper purus. Quisque id congue odio. Quisque imperdiet id velit nec " +
		"placerat. Nunc blandit, orci in volutpat congue, orci eros congue lectus, sit amet elementum ligula dui vitae " +
		"ligula. Proin tincidunt facilisis risus, non tempus ex semper eu. Vivamus ultrices magna et posuere finibus." +
		"\n\nNunc blandit, enim ullamcorper viverra scelerisque, quam magna volutpat justo, quis placerat augue magna " +
		"eget sapien. In dignissim magna nisi, vel fermentum turpis consequat eget. Aenean consequat pretium nulla non " +
		"blandit. Vestibulum sodales nibh vel sapien aliquet, vitae rhoncus metus suscipit. Nulla non mi accumsan, " +
		"tincidunt dui at, iaculis nisl. Aliquam convallis finibus ipsum. Quisque id massa vestibulum, congue velit eu," +
		" viverra orci. Vivamus metus metus, dictum non porta posuere, commodo sit amet arcu. "

	metahash := "2da39247e2a131dd97fb311e0c477cde445e3d3269599fdd119ff2c1ae1199a6"

	node1.AnonymousPublishArticle(types.ArticleSummaryMessage{
		ArticleID: xid.New().String(),
		Title:     title,
	}, content)
	// Enough time for the message to reach node2.
	time.Sleep(time.Second * 2)

	ins2 := node2.GetIns()
	var address string
	var rumors types.RumorsMessage
	for _, x := range ins2 {
		if x.Msg.Type == (types.RumorsMessage{}).Name() {
			json.Unmarshal(x.Msg.Payload, &rumors)
			break
		}
	}
	address = rumors.Rumors[0].Origin

	require.NotEqual(t, node1.GetAddr(), address)

	for _, dirNode := range directoryServers {
		if dirNode.GetStorage().GetDataBlobStore().Len() > 0 {
			require.Equal(t, metahash, string(dirNode.GetStorage().GetNamingStore().Get(title)))
			break
		}
	}
}

func Test_Tor_Anonymous_Download(t *testing.T) {

	udp := udp.NewUDP()

	directoryServers := startDirectoryNodes(udp, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	defer node2.Stop()
	time.Sleep(time.Second * 2)

	title := "LoremIpsum"
	content := " Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam varius maximus tellus, vel congue nunc" +
		" efficitur a. Duis vel sagittis lacus, a vulputate massa. Maecenas molestie tempor felis sit amet sodales. " +
		"Pellentesque porttitor convallis neque, iaculis maximus quam scelerisque blandit. Maecenas euismod nibh mi, " +
		"vel egestas mi vulputate ut. Mauris iaculis mattis est sed sodales. Mauris hendrerit malesuada lectus ut " +
		"dictum.\n\nDonec ornare lectus nec nunc maximus, at posuere ante posuere. Quisque finibus ex facilisis, " +
		"tristique elit eu, pulvinar ex. Curabitur accumsan at ex quis condimentum. Pellentesque mi nulla, tempor " +
		"posuere tellus fermentum, porta ullamcorper purus. Quisque id congue odio. Quisque imperdiet id velit nec " +
		"placerat. Nunc blandit, orci in volutpat congue, orci eros congue lectus, sit amet elementum ligula dui vitae " +
		"ligula. Proin tincidunt facilisis risus, non tempus ex semper eu. Vivamus ultrices magna et posuere finibus." +
		"\n\nNunc blandit, enim ullamcorper viverra scelerisque, quam magna volutpat justo, quis placerat augue magna " +
		"eget sapien. In dignissim magna nisi, vel fermentum turpis consequat eget. Aenean consequat pretium nulla non " +
		"blandit. Vestibulum sodales nibh vel sapien aliquet, vitae rhoncus metus suscipit. Nulla non mi accumsan, " +
		"tincidunt dui at, iaculis nisl. Aliquam convallis finibus ipsum. Quisque id massa vestibulum, congue velit eu," +
		" viverra orci. Vivamus metus metus, dictum non porta posuere, commodo sit amet arcu. "

	mh := "2da39247e2a131dd97fb311e0c477cde445e3d3269599fdd119ff2c1ae1199a6"

	data := bytes.NewBuffer([]byte(content))

	metahash, err := node2.Upload(data)
	require.NoError(t, err)
	require.Equal(t, mh, metahash)

	node2.GetStorage().GetNamingStore().Set(title, []byte(metahash))
	require.Equal(t, 1, node2.GetStorage().GetNamingStore().Len())

	err = node1.AnonymousDownloadArticle(title, metahash)
	time.Sleep(time.Second * 1)
	require.NoError(t, err)

	// Check if node1 got the article.
	require.Equal(t, 1, node1.GetStorage().GetDataBlobStore().Len())

	// Check if some directory node downloaded the article, since one of them will be the exit node
	// in node1's circuit.
	for _, dirNode := range directoryServers {
		if dirNode.GetStorage().GetDataBlobStore().Len() != 0 {
			require.Equal(t, metahash, string(dirNode.GetStorage().GetNamingStore().Get(title)))
			break
		}
	}

}

//----------------------------------Helper functions---------------------------------------------

func startDirectoryNodes(udp transport.Transport, t *testing.T) []z.TestNode {

	directoryNode1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2000", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2001", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode3 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2002", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode4 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2003", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode5 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2004", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode6 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2005", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode7 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2006", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode8 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2007", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode9 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2008", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))
	directoryNode10 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:2009", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes()),
		z.WithPrivateKey(generateRSAKey()))

	return []z.TestNode{directoryNode1, directoryNode2, directoryNode3, directoryNode4, directoryNode5,
		directoryNode6, directoryNode7, directoryNode8, directoryNode9, directoryNode10}

}

func generateDHParameters() (*big.Int, *big.Int, *big.Int) {

	p := new(big.Int).SetInt64(0)
	q := new(big.Int).SetInt64(0)
	g := new(big.Int).SetInt64(4)
	p.SetString("8647319109379464648021925294796689066105386151280946525511859837403996775216573885094628284957162731767740284972116962623790686696231246098821762507813723", 10)
	q.SetString("4323659554689732324010962647398344533052693075640473262755929918701998387608286942547314142478581365883870142486058481311895343348115623049410881253906861", 10)

	return p, q, g
}

func getDirectoryNodes() []string {
	return []string{"127.0.0.1:2000", "127.0.0.1:2001", "127.0.0.1:2002", "127.0.0.1:2003", "127.0.0.1:2004",
		"127.0.0.1:2005", "127.0.0.1:2006", "127.0.0.1:2007", "127.0.0.1:2008", "127.0.0.1:2009"}
}

func generateRSAKey() *rsa.PrivateKey {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}
