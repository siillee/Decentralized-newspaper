package unit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl/concurrent"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/types"
)

// Send an article summary followed by a vote for that article.
// Check if both messages were recorded as expected in the vote store.
func Test_Sybil_Valid_Vote(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	voteKeys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: "article 1",
		UserID:    sock2.GetAddress(),
		Title:     "article 1 title",
		Metahash:  "meta hash 1",
		Timestamp: time.Now(),
	}
	signature, err := articleSummaryMessage.Sign(keys2)
	require.NoError(t, err)
	articleSummaryMessage.Signature = signature
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&voteKeys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pubBytes,
		Timestamp: time.Now(),
	}
	signBytes, err := voteMessage.Sign(voteKeys)
	require.NoError(t, err)
	voteMessage.Signature = signBytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 1)
	require.Equal(t, string(pubBytes), voters[0])
}

// Send a vote for an article that doesn't exist (or hasn't been received yet).
// Check if no valid articles are recorded, but vote is recorded
// (so it can be applied once summary is received).
func Test_Sybil_Invalid_Vote(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	voteKeys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	pubBytes, err := x509.MarshalPKIXPublicKey(&voteKeys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pubBytes,
		Timestamp: time.Now(),
	}
	signBytes, err := voteMessage.Sign(voteKeys)
	require.NoError(t, err)
	voteMessage.Signature = signBytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 0)

	voters := voteStore.Get("article 1")
	require.Len(t, voters, 1)
	require.Equal(t, string(pubBytes), voters[0])
}

// Send an article summary followed by a vote with a mismatched signature.
// Check if the vote has been correctly ignored.
func Test_Sybil_Vote_Bad_Signature(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	voteKeys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: "article 1",
		UserID:    sock2.GetAddress(),
		Title:     "article 1 title",
		Metahash:  "meta hash 1",
		Timestamp: time.Now(),
	}
	signature, err := articleSummaryMessage.Sign(keys2)
	require.NoError(t, err)
	articleSummaryMessage.Signature = signature
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&voteKeys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pubBytes,
		Timestamp: time.Now(),
	}
	signBytes, err := voteMessage.Sign(keys1)
	require.NoError(t, err)
	voteMessage.Signature = signBytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 0)
}

// Send 2 votes for an article and make sure both are recorded.
func Test_Sybil_No_Timeouts(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote1Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote2Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(1000*time.Second))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	moment1 := time.Now()
	moment2 := moment1.Add(10 * time.Second)
	moment3 := moment1.Add(200 * time.Second)

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: "article 1",
		UserID:    sock2.GetAddress(),
		Title:     "article 1 title",
		Metahash:  "meta hash 1",
		Timestamp: moment1,
	}
	signature, err := articleSummaryMessage.Sign(keys2)
	require.NoError(t, err)
	articleSummaryMessage.Signature = signature
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pub1Bytes, err := x509.MarshalPKIXPublicKey(&vote1Keys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub1Bytes,
		Timestamp: moment2,
	}
	sign1Bytes, err := voteMessage.Sign(vote1Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign1Bytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pub2Bytes, err := x509.MarshalPKIXPublicKey(&vote2Keys.PublicKey)
	require.NoError(t, err)
	voteMessage = types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub2Bytes,
		Timestamp: moment3,
	}
	sign2Bytes, err := voteMessage.Sign(vote2Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign2Bytes
	voteTransportMessage, err = types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 2)
	require.Contains(t, voters, string(pub1Bytes))
	require.Contains(t, voters, string(pub2Bytes))
}

// Send 2 votes for an article and make sure one is timed out.
func Test_Sybil_Vote_Timeout(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote1Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote2Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(100*time.Second))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	moment1 := time.Now()
	moment2 := moment1.Add(10 * time.Second)
	moment3 := moment1.Add(200 * time.Second)

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: "article 1",
		UserID:    sock2.GetAddress(),
		Title:     "article 1 title",
		Metahash:  "meta hash 1",
		Timestamp: moment1,
	}
	signature, err := articleSummaryMessage.Sign(keys2)
	require.NoError(t, err)
	articleSummaryMessage.Signature = signature
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pub1Bytes, err := x509.MarshalPKIXPublicKey(&vote1Keys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub1Bytes,
		Timestamp: moment3,
	}
	sign1Bytes, err := voteMessage.Sign(vote1Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign1Bytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pub2Bytes, err := x509.MarshalPKIXPublicKey(&vote2Keys.PublicKey)
	require.NoError(t, err)
	voteMessage = types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub2Bytes,
		Timestamp: moment2,
	}
	sign2Bytes, err := voteMessage.Sign(vote2Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign2Bytes
	voteTransportMessage, err = types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 1)
	require.Contains(t, voters, string(pub2Bytes))
}

// Send 2 votes for an article and send the summary afterwards. One of the votes should be timed out.
func Test_Sybil_Vote_Timeout_After(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote1Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote2Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(100*time.Second))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	moment1 := time.Now()
	moment2 := moment1.Add(10 * time.Second)
	moment3 := moment1.Add(200 * time.Second)

	pub1Bytes, err := x509.MarshalPKIXPublicKey(&vote1Keys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub1Bytes,
		Timestamp: moment3,
	}
	sign1Bytes, err := voteMessage.Sign(vote1Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign1Bytes
	voteTransportMessage, err := types.ToTransport(voteMessage)
	require.NoError(t, err)
	header := transport.NewHeader(
		sock2.GetAddress(), // source
		sock2.GetAddress(), // relay
		node1.GetAddr(),    // destination
		0,                  // TTL
	)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	pub2Bytes, err := x509.MarshalPKIXPublicKey(&vote2Keys.PublicKey)
	require.NoError(t, err)
	voteMessage = types.VoteMessage{
		ArticleID: "article 1",
		PublicKey: pub2Bytes,
		Timestamp: moment2,
	}
	sign2Bytes, err := voteMessage.Sign(vote2Keys)
	require.NoError(t, err)
	voteMessage.Signature = sign2Bytes
	voteTransportMessage, err = types.ToTransport(voteMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &voteTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 0)

	voters := voteStore.Get("article 1")
	require.Len(t, voters, 2)
	require.Contains(t, voters, string(pub1Bytes))
	require.Contains(t, voters, string(pub2Bytes))

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: "article 1",
		UserID:    sock2.GetAddress(),
		Title:     "article 1 title",
		Metahash:  "meta hash 1",
		Timestamp: moment1,
	}
	signature, err := articleSummaryMessage.Sign(keys2)
	require.NoError(t, err)
	articleSummaryMessage.Signature = signature
	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	require.NoError(t, err)
	pkt = transport.Packet{
		Header: &header,
		Msg:    &articleSummaryTransportMessage,
	}

	err = sock2.Send(node1.GetAddr(), pkt, 0)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	voteStore, ok = node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles = voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters = voteStore.Get(articles[0])
	require.Len(t, voters, 1)
	require.Contains(t, voters, string(pub2Bytes))
}
