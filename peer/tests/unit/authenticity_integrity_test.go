package unit

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
	"testing"
	"time"
)

func Test_Authenticity_Integrity_Summary_Valid(t *testing.T) {
	transp := channel.NewTransport()

	keys1, err := rsa.GenerateKey(rand.Reader, 2048) // this generates a public & private key pair
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	keys2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys2))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	node1.AddPublicKey(keys2.PublicKey, node2.GetAddr())
	node2.AddPublicKey(keys1.PublicKey, node1.GetAddr())

	time.Sleep(2 * time.Second)

	title := "My article"
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

	data := bytes.NewBuffer([]byte(content))

	articleID, err := node1.PublishArticle(title, data)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	require.NotEmpty(t, node2.GetSummary(articleID))
}

// A malicious node tries to send a summary supposedly coming from node 2
func Test_Authenticity_Integrity_Summary_Invalid(t *testing.T) {
	transp := channel.NewTransport()

	keys1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	keys2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys2))
	defer node2.Stop()

	node1.AddPublicKey(keys2.PublicKey, node2.GetAddr())
	node2.AddPublicKey(keys1.PublicKey, node1.GetAddr())

	keys3, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	sock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock.Close()

	node1.AddPublicKey(keys3.PublicKey, sock.GetAddress())
	node2.AddPublicKey(keys3.PublicKey, sock.GetAddress())

	time.Sleep(2 * time.Second)

	title := "No one should trust this article"
	articleID := xid.New().String()
	h := crypto.SHA256.New()
	h.Write([]byte("don't trust me"))
	metahash := h.Sum(nil)

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: articleID,
		Title:     title,
		//ShortDescription: shortDescription,
		Metahash: string(metahash),
		UserID:   node2.GetAddr(),
	}
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)

	header := transport.NewHeader(
		node2.GetAddr(), // source
		node2.GetAddr(), // relay
		node1.GetAddr(), // destination
		0,               // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	require.Empty(t, node1.GetSummary(articleID))
}
