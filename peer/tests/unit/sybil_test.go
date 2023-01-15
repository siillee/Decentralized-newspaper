package unit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math"
	mrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	log "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/peer/impl/concurrent"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
	"go.dedis.ch/cs438/transport/udp"
	"go.dedis.ch/cs438/types"
)

// Send an article summary followed by a vote for that article.
// Check if both messages were recorded as expected in the vote store.
func Test_Sybil_Vote_Valid(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	voteKeys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithProofDifficulty(0))
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
		Timestamp: time.Now(),
		Proof:     0,
		PublicKey: pubBytes,
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

	time.Sleep(1 * time.Second)

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
func Test_Sybil_Vote_Invalid(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	voteKeys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithProofDifficulty(0))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	pubBytes, err := x509.MarshalPKIXPublicKey(&voteKeys.PublicKey)
	require.NoError(t, err)
	voteMessage := types.VoteMessage{
		ArticleID: "article 1",
		Timestamp: time.Now(),
		Proof:     0,
		PublicKey: pubBytes,
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

	time.Sleep(1 * time.Second)

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithProofDifficulty(0))
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
		Timestamp: time.Now(),
		Proof:     0,
		PublicKey: pubBytes,
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

	time.Sleep(1 * time.Second)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 0)
}

// Send 2 votes for an article and make sure both are recorded.
func Test_Sybil_Vote_No_Timeouts(t *testing.T) {
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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(1000*time.Second), z.WithProofDifficulty(0))
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
		Timestamp: moment2,
		Proof:     0,
		PublicKey: pub1Bytes,
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
		Timestamp: moment3,
		Proof:     0,
		PublicKey: pub2Bytes,
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

	time.Sleep(1 * time.Second)

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(100*time.Second), z.WithProofDifficulty(0))
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
		Timestamp: moment3,
		Proof:     0,
		PublicKey: pub1Bytes,
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
		Timestamp: moment2,
		Proof:     0,
		PublicKey: pub2Bytes,
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

	time.Sleep(1 * time.Second)

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

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithVoteTimeout(100*time.Second), z.WithProofDifficulty(0))
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
		Timestamp: moment3,
		Proof:     0,
		PublicKey: pub1Bytes,
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
		Timestamp: moment2,
		Proof:     0,
		PublicKey: pub2Bytes,
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

	time.Sleep(1 * time.Second)

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

	time.Sleep(1 * time.Second)

	voteStore, ok = node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles = voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters = voteStore.Get(articles[0])
	require.Len(t, voters, 1)
	require.Contains(t, voters, string(pub2Bytes))
}

// Send an article summary, and then send a vote for it. Don't bother calculating the proof.
// Vote should not be recorded because the proof was not provided.
func Test_Sybil_Vote_Proof_Invalid(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	vote1Keys, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1), z.WithCheckProofThreshold(0), z.WithProofDifficulty(8))
	defer node1.Stop()

	sock2, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer sock2.Close()

	node1.AddPublicKey(keys2.PublicKey, sock2.GetAddress())

	moment1 := time.Now()
	moment2 := moment1.Add(10 * time.Second)

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
		Timestamp: moment2,
		Proof:     0,
		PublicKey: pub1Bytes,
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

	time.Sleep(1 * time.Second)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)
	require.Equal(t, "article 1", articles[0])

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 0)
}

// Send an article summary, and then send a vote for it. Calculate the proof.
// Vote should be recorded because a valid proof of work was provided.
func Test_Sybil_Vote_Proof_Valid(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1),
		z.WithCheckProofThreshold(0), z.WithProofDifficulty(8))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys2),
		z.WithCheckProofThreshold(0), z.WithProofDifficulty(8))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	node1.AddPublicKey(keys2.PublicKey, node2.GetAddr())
	node2.AddPublicKey(keys1.PublicKey, node1.GetAddr())

	time.Sleep(1 * time.Second)

	articleID, err := node1.PublishArticle("article 1", bytes.NewBuffer([]byte("placeholder content")))
	require.NoError(t, err)

	err = node2.Like(articleID)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articles := voteStore.GetArticles()
	require.Len(t, articles, 1)

	voters := voteStore.Get(articles[0])
	require.Len(t, voters, 1)
}

// Send an article summary. Then keep sending votes for it until the vote is registered.
// Meanwhile the other thread is calculating the proof.
// Vote should be recorded once the proof is successfully calculated.
// Test can be used to estimate the processing time for a specific difficulty.
func Test_Sybil_Vote_Proof_Performance(t *testing.T) {
	transp := channel.NewTransport()

	EC := elliptic.P256()

	keys1, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)
	keys2, err := ecdsa.GenerateKey(EC, rand.Reader)
	require.NoError(t, err)

	difficulty := 18
	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys1),
		z.WithCheckProofThreshold(0), z.WithProofDifficulty(uint(difficulty)))
	defer node1.Stop()
	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithPrivateKey(keys2),
		z.WithCheckProofThreshold(0), z.WithProofDifficulty(uint(difficulty)))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	node1.AddPublicKey(keys2.PublicKey, node2.GetAddr())
	node2.AddPublicKey(keys1.PublicKey, node1.GetAddr())

	articleID, err := node1.PublishArticle("article 1", bytes.NewBuffer([]byte("placeholder content")))
	require.NoError(t, err)

	notReceived := true
	for notReceived {
		time.Sleep(45 * time.Millisecond)

		err = node2.Like(articleID)
		require.NoError(t, err)

		time.Sleep(5 * time.Millisecond)

		voteStore, ok := node1.GetVoteStore().(concurrent.VoteStore)
		require.True(t, ok)

		articles := voteStore.GetArticles()
		require.Len(t, articles, 1)

		voters := voteStore.Get(articles[0])
		if len(voters) == 1 {
			notReceived = false
		} else {
			require.Len(t, voters, 0)
		}
	}
}

// Two nodes. Some articles are published. Node 1 likes two articles. Node 2 likes the first article node 1 liked.
// Node 2 is expected to get the second article node 1 liked in their recommendations.
func Test_Sybil_Recommended_After_One_Vote(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10), z.WithProofDifficulty(0))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10), z.WithProofDifficulty(0))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	type articleObj struct {
		title   string
		content string
		id      string
	}
	articles := []articleObj{
		{
			title:   "Article 1",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 2",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 3",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 4",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 5",
			content: "---Placeholder content---",
		}}

	for i, art := range articles {
		data := bytes.NewBuffer([]byte(art.content))

		articleID, err := node1.PublishArticle(art.title, data)
		require.NoError(t, err)

		art.id = articleID
		articles[i] = art
	}

	time.Sleep(1 * time.Second)

	goodArticleIndexes := []int{1, 3}
	goodArticleIDs := make([]string, 0)

	for i, art := range articles {
		isBad := true
		for _, ind := range goodArticleIndexes {
			if i == ind {
				isBad = false
			}
		}
		if isBad {
			continue
		}

		err := node1.Like(art.id)
		require.NoError(t, err)

		goodArticleIDs = append(goodArticleIDs, art.id)
	}

	time.Sleep(1 * time.Second)

	err := node2.Like(goodArticleIDs[0])
	require.NoError(t, err)

	status := node2.RefreshRecommendations()
	require.Equal(t, impl.RecSuccess, status)

	recs := node2.GetRecommendations()
	require.Len(t, recs, 1)
	require.Equal(t, goodArticleIDs[1], recs[0])
}

// Two nodes. Some articles are published. Node 1 likes two articles.
// A bot sends 10 votes for a bad article.
// Node 2 likes the first article node 1 liked.
// Node 2 is expected to get the second article node 1 liked in their recommendations.
func Test_Sybil_Recommended_With_Botting(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10), z.WithProofDifficulty(0))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10), z.WithProofDifficulty(0))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	type articleObj struct {
		title   string
		content string
		id      string
	}
	articles := []articleObj{
		{
			title:   "Article 1",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 2",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 3",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 4",
			content: "---Placeholder content---",
		},
		{
			title:   "Article 5",
			content: "---Placeholder content---",
		}}

	for i, art := range articles {
		data := bytes.NewBuffer([]byte(art.content))

		articleID, err := node1.PublishArticle(art.title, data)
		require.NoError(t, err)

		art.id = articleID
		articles[i] = art
	}

	badArticleIndex := 0
	goodArticleIndexes := []int{1, 3}
	goodArticleIDs := make([]string, 0)

	for i, art := range articles {
		isBad := true
		for _, ind := range goodArticleIndexes {
			if i == ind {
				isBad = false
			}
		}
		if isBad {
			continue
		}

		err := node1.Like(art.id)
		require.NoError(t, err)

		goodArticleIDs = append(goodArticleIDs, art.id)
	}

	botSock, err := transp.CreateSocket("127.0.0.1:0")
	require.NoError(t, err)
	defer botSock.Close()

	EC := elliptic.P256()

	for i := 0; i < 10; i++ {
		keys, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
		require.NoError(t, err)

		pubBytes, err := x509.MarshalPKIXPublicKey(&keys.PublicKey)
		require.NoError(t, err)
		voteMessage := types.VoteMessage{
			ArticleID: articles[badArticleIndex].id,
			Timestamp: time.Now(),
			Proof:     0,
			PublicKey: pubBytes,
		}
		signBytes, err := voteMessage.Sign(keys)
		require.NoError(t, err)
		voteMessage.Signature = signBytes
		voteTransportMessage, err := types.ToTransport(voteMessage)
		require.NoError(t, err)
		header := transport.NewHeader(
			botSock.GetAddress(), // source
			botSock.GetAddress(), // relay
			node2.GetAddr(),      // destination
			0,                    // TTL
		)
		pkt := transport.Packet{
			Header: &header,
			Msg:    &voteTransportMessage,
		}

		err = botSock.Send(node2.GetAddr(), pkt, 0)
		require.NoError(t, err)
	}

	time.Sleep(2 * time.Second)

	voteStore, ok := node2.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articleVotes := voteStore.GetArticles()
	require.Len(t, articleVotes, len(articles))

	for i, art := range articles {
		isBad := i == badArticleIndex
		isGood := false
		for _, j := range goodArticleIndexes {
			if i == j {
				isGood = true
			}
		}

		voters := voteStore.Get(art.id)

		if isBad {
			require.Len(t, voters, 10)
		} else if isGood {
			require.Len(t, voters, 1)
		} else {
			require.Len(t, voters, 0)
		}
	}

	err = node2.Like(goodArticleIDs[0])
	require.NoError(t, err)

	status := node2.RefreshRecommendations()
	require.Equal(t, impl.RecSuccess, status)

	recs := node2.GetRecommendations()
	require.Len(t, recs, 1)
	require.Equal(t, goodArticleIDs[1], recs[0])
}

func Test_Sybil_Scenario(t *testing.T) {
	transp := udp.NewUDP()

	node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1),
		z.WithOverwhelmingThreshold(100.0), z.WithInitialScore(10.0), z.WithPositiveFactor(16.0), z.WithNegativeFactor(1_048_576.0),
		z.WithCheckProofThreshold(1_000_000), z.WithProofDifficulty(4))
	defer node.Stop()

	numOfGoodArticles := 500
	numOfBadArticles := 500

	nodeNum := 10
	userGoodChance := 0.19
	userBadChance := 0.005

	botNetSize := 1_000
	botGoodChance := 0.06
	botBadChance := 0.3

	feedCycles := 300

	// Article creation set-up
	type articleObj struct {
		title   string
		content string
		id      string
	}

	goodArticles := make([]articleObj, numOfGoodArticles)
	badArticles := make([]articleObj, numOfBadArticles)

	// Create good articles
	for i := 0; i < numOfGoodArticles; i++ {
		art := articleObj{
			title:   fmt.Sprintf("Good Article #%v", i),
			content: "---Placeholder content---",
			id:      "TODO: replace me",
		}

		goodArticles[i] = art
	}

	// Create bad articles
	for i := 0; i < numOfBadArticles; i++ {
		art := articleObj{
			title:   fmt.Sprintf("Bad Article #%v", i),
			content: "---Placeholder content---",
			id:      "TODO: replace me",
		}

		badArticles[i] = art
	}

	// Publish good articles
	for i, art := range goodArticles {
		data := bytes.NewBuffer([]byte(art.content))

		articleID, err := node.PublishArticle(art.title, data)
		require.NoError(t, err)

		art.id = articleID
		goodArticles[i] = art
	}

	// Publish bad articles
	for i, art := range badArticles {
		data := bytes.NewBuffer([]byte(art.content))

		articleID, err := node.PublishArticle(art.title, data)
		require.NoError(t, err)

		art.id = articleID
		badArticles[i] = art
	}

	time.Sleep(1 * time.Second)

	// Voting sim set-up
	EC := elliptic.P256()

	voteStore, ok := node.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	botVoteFun := func(articleID string, publicKey []byte, privateKey *ecdsa.PrivateKey) {
		voteMessage := types.VoteMessage{
			ArticleID: articleID,
			Timestamp: time.Now(),
			Proof:     0,
			PublicKey: publicKey,
		}
		signBytes, err := voteMessage.Sign(privateKey)
		require.NoError(t, err)
		voteMessage.Signature = signBytes
		voteStore.Add(voteMessage)
	}

	simulateVotingPattern := func(numOfBots int, goodChance float64, badChance float64) {
		for i := 0; i < numOfBots; i++ {
			if i%100 == 0 {
				log.Logger.Info().Msgf("ping from simulateVotingPattern...")
			}
			keys, err := ecdsa.GenerateKey(EC, rand.Reader) // this generates a public & private key pair
			require.NoError(t, err)

			pubBytes, err := x509.MarshalPKIXPublicKey(&keys.PublicKey)
			require.NoError(t, err)

			// Bot voting for good articles
			for _, art := range goodArticles {
				roll := mrand.Float64()

				if roll >= goodChance {
					continue
				}

				botVoteFun(art.id, pubBytes, keys)
			}
			// Bot voting for bad articles
			for _, art := range badArticles {
				roll := mrand.Float64()

				if roll >= badChance {
					continue
				}

				botVoteFun(art.id, pubBytes, keys)
			}
		}
	}

	// Simulate node article voting
	simulateVotingPattern(nodeNum, userGoodChance, userBadChance)

	// Simulate sybil attack
	simulateVotingPattern(botNetSize, botGoodChance, botBadChance)

	// Check the vote store
	voteStore, ok = node.GetVoteStore().(concurrent.VoteStore)
	require.True(t, ok)

	articleVotes := voteStore.GetArticles()
	require.Len(t, articleVotes, len(goodArticles)+len(badArticles))

	goodVoteCount := 0
	badVoteCount := 0
	for _, art := range goodArticles {
		voters := voteStore.Get(art.id)
		goodVoteCount += len(voters)
	}
	for _, art := range badArticles {
		voters := voteStore.Get(art.id)
		badVoteCount += len(voters)
	}

	// Simulate new user's experience using the feed
	log.Logger.Info().Msgf("starting user experience simulation...")
	goodRecs := 0
	badRecs := 0
	for i := 0; i < feedCycles; i++ {
		status := node.RefreshRecommendations()
		require.Equal(t, impl.RecSuccess, status)

		recs := node.GetRecommendations()
		require.Len(t, recs, 1)

		articleID := recs[0]
		summary := node.GetSummary(articleID)
		if strings.HasPrefix(summary.Title, "Good") {
			err := node.Like(articleID)
			require.NoError(t, err)
			goodRecs++
		} else {
			node.Dislike(articleID)
			badRecs++
		}
	}

	M := botNetSize
	D := 5.0
	expectedLoss := math.Log2(float64(M)) * D
	marginOfError := 2 * expectedLoss
	log.Logger.Info().Msgf("loss is %v (%v%%)", badRecs, (100.0 * float64(badRecs) / float64(feedCycles)))
	require.Less(t, float64(badRecs), marginOfError)
}
