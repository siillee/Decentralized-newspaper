package unit

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
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

func Test_Tor_Circuit_Create_Single(t *testing.T) {

	udp := udp.NewUDP()
	privateKeys := generateRSAKeys(10)
	dir := getDirectory(privateKeys)

	directoryServers := startNodes(udp, 10, true, dir, privateKeys, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
		z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir))
	defer node1.Stop()

	for _, server := range directoryServers {
		server.AddPeer(node1.GetAddr())
	}

	circuit, err := node1.CreateRandomCircuit()
	require.NoError(t, err)
	require.Len(t, circuit.AllSharedKeys, 3)
}

func Test_Tor_Circuit_Create_Multiple(t *testing.T) {

	udp := udp.NewUDP()
	privateKeys := generateRSAKeys(10)
	dir := getDirectory(privateKeys)

	directoryServers := startNodes(udp, 10, true, dir, privateKeys, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	testNodes := startNodes(udp, 100, false, dir, privateKeys, t)
	for _, node := range testNodes {
		defer node.Stop()
	}

	for _, node := range testNodes {
		createCicruit(node, t)
	}

	time.Sleep(time.Second * 5)
}

func Test_Tor_Anonymous_Broadcast(t *testing.T) {

	udp := udp.NewUDP()
	privateKeys := generateRSAKeys(10)
	dir := getDirectory(privateKeys)

	directoryServers := startNodes(udp, 10, true, dir, privateKeys, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
		z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
		z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	for _, server := range directoryServers {
		server.AddPeer(node1.GetAddr(), node2.GetAddr())
	}

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
	time.Sleep(time.Second * 3)

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
	privateKeys := generateRSAKeys(10)
	dir := getDirectory(privateKeys)

	directoryServers := startNodes(udp, 10, true, dir, privateKeys, t)
	for _, server := range directoryServers {
		defer server.Stop()
	}

	node1 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
		z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, udp, "127.0.0.1:0", z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
		z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir))
	defer node2.Stop()

	for _, server := range directoryServers {
		server.AddPeer(node1.GetAddr())
		server.AddPeer(node2.GetAddr())
	}

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

	// node2.GetStorage().GetNamingStore().Set(title, []byte(metahash))
	node2.Tag(title, metahash)
	require.Equal(t, 1, node2.GetStorage().GetNamingStore().Len())

	err = node1.AnonymousDownloadArticle(title, metahash)
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

func startNodes(udp transport.Transport, num int, directory bool, dir []types.TorNode, keys []*rsa.PrivateKey, t *testing.T) []z.TestNode {

	result := make([]z.TestNode, 0)
	if directory {
		address := ""
		for i := 0; i < num; i++ {
			if i < 10 {
				address = "127.0.0.1:200" + fmt.Sprint(i)
			} else {
				address = "127.0.0.1:20" + fmt.Sprint(i)
			}
			result = append(result, z.NewTestNode(t, peerFac, udp, address, z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(num)),
				z.WithPrivateKey(keys[i]), z.WithDirectory(dir)))
		}
	} else {
		address := "127.0.0.1:0"
		for i := 0; i < num; i++ {
			result = append(result, z.NewTestNode(t, peerFac, udp, address, z.WithDHParams(generateDHParameters()), z.WithDirectoryNodes(getDirectoryNodes(10)),
				z.WithPrivateKey(generateRSAKey()), z.WithDirectory(dir)))
		}
	}

	return result
}

func generateRSAKeys(num int) []*rsa.PrivateKey {

	result := make([]*rsa.PrivateKey, 0)
	for i := 0; i < num; i++ {
		result = append(result, generateRSAKey())
	}

	return result
}

func getDirectory(keys []*rsa.PrivateKey) []types.TorNode {

	result := make([]types.TorNode, 0)

	for i := 0; i < len(keys); i++ {
		if i < 10 {
			result = append(result, types.TorNode{Ip: "127.0.0.1:200" + fmt.Sprint(i), Pk: &keys[i].PublicKey})
		} else {
			result = append(result, types.TorNode{Ip: "127.0.0.1:20" + fmt.Sprint(i), Pk: &keys[i].PublicKey})
		}
	}

	return result
}

func generateDHParameters() (*big.Int, *big.Int, *big.Int) {

	p := new(big.Int).SetInt64(0)
	q := new(big.Int).SetInt64(0)
	g := new(big.Int).SetInt64(4)
	p.SetString("8647319109379464648021925294796689066105386151280946525511859837403996775216573885094628284957162731767740284972116962623790686696231246098821762507813723", 10)
	q.SetString("4323659554689732324010962647398344533052693075640473262755929918701998387608286942547314142478581365883870142486058481311895343348115623049410881253906861", 10)

	return p, q, g
}

func getDirectoryNodes(num int) []string {

	result := make([]string, 0)

	for i := 0; i < num; i++ {
		if i < 10 {
			result = append(result, "127.0.0.1:200"+fmt.Sprint(i))
		} else {
			result = append(result, "127.0.0.1:20"+fmt.Sprint(i))
		}
	}

	return result
}

func generateRSAKey() *rsa.PrivateKey {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

func createCicruit(node z.TestNode, t *testing.T) {
	go func() {
		circuit, err := node.CreateRandomCircuit()
		require.NoError(t, err)
		require.Len(t, circuit.AllSharedKeys, 3)
	}()
}
