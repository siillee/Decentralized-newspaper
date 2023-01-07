package unit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/peer/impl"
	"go.dedis.ch/cs438/peer/impl/concurrent"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
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
func Test_Sybil_Vote_Invalid(t *testing.T) {
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

// Two nodes. Some articles are published. Node 1 likes two articles. Node 2 likes the first article node 1 liked.
// Node 2 is expected to get the second article node 1 liked in their recommendations.
func Test_Sybil_Recommended_After_One_Vote(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	time.Sleep(2 * time.Second)

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

	time.Sleep(50 * time.Millisecond)

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
		z.WithInitialScore(10))
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithHeartbeat(time.Second*200),
		z.WithAntiEntropy(time.Second*5), z.WithRecommendationSetSize(1), z.WithOverwhelmingThreshold(10),
		z.WithInitialScore(10))
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	time.Sleep(2 * time.Second)

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
			PublicKey: pubBytes,
			Timestamp: time.Now(),
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

	time.Sleep(50 * time.Millisecond)

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
