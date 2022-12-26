package unit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
	"testing"
	"time"
)

func Test_Authenticity_Integrity_Summary(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
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
