package unit

import (
	"fmt"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
	"math/big"
	"testing"
)

func Test_DH_Correct_Secret(t *testing.T) {
	transp := channel.NewTransport()

	p := new(big.Int).SetInt64(0)
	q := new(big.Int).SetInt64(0)
	g := new(big.Int).SetInt64(4)
	p.SetString("46356762339281014666653110981182053309710174465125249347701816812383941408747", 10)
	q.SetString("23178381169640507333326555490591026654855087232562624673850908406191970704373", 10)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithDHParams(p, q, g))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithDHParams(p, q, g))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	secret1, err := node1.EstablishKeyExchange(node2.GetAddr())
	require.NoError(t, err)

	secret2 := node2.GetSharedSecret(node1.GetAddr())
	fmt.Println(secret1)
	fmt.Println(secret2)
	require.Equal(t, secret1.Cmp(&secret2), 0)
}
