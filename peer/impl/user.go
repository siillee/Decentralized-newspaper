package impl

import (
	"crypto/ecdsa"
	"crypto/x509"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

func (n *node) PublishArticle(title string, content io.Reader) (string, error) {
	metaHash, err := n.Upload(content)
	if err != nil {
		return "", err
	}

	//blobStore := n.conf.Storage.GetDataBlobStore()
	//metafile := blobStore.Get(metaHash)
	//chunkHexKeys := strings.Split(string(metafile), peer.MetafileSep)
	//firstChunkData := blobStore.Get(chunkHexKeys[0])
	//shortDescription := string(firstChunkData[:150])

	articleID := xid.New().String()

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID: articleID,
		Title:     title,
		//ShortDescription: shortDescription,
		Metahash:  metaHash,
		Timestamp: time.Now(),
	}

	isUsingTor := false //add signature only if not anonymous and if it has a privateKey
	if !isUsingTor && n.conf.PrivateKey != nil {
		articleSummaryMessage.UserID = n.GetAddress()
		signature, err := articleSummaryMessage.Sign(n.conf.PrivateKey)
		if err != nil {
			return "", err
		}
		articleSummaryMessage.Signature = signature
	}

	articleSummaryTransportMessage, err := types.ToTransport(articleSummaryMessage)
	if err != nil {
		return "", err
	}

	_ = n.Tag(title, metaHash)

	err = n.Broadcast(articleSummaryTransportMessage)
	return articleID, err
}

func (n *node) DownloadArticle(title, metahash string) ([]byte, error) {
	// check if article exists locally
	if n.hasAllChunks(metahash) {
		return n.Download(metahash) //local download
	}

	reg := *regexp.MustCompile(title)
	responses, err := n.SearchAll(reg, 15, time.Millisecond*100) //update catalog
	if err != nil {
		return nil, err
	}
	if len(responses) == 0 {
		return nil, xerrors.Errorf("Article Not found")
	}

	content, err := n.Download(metahash)
	if err != nil {
		return nil, err
	}

	// check metahash
	nChunks := int(math.Ceil(float64(len(content)) / float64(n.conf.ChunkSize)))
	_, chunks := n.DivideIntoChunks(content, nChunks)
	metahashOutput := n.ComputeMetaHash(chunks, nChunks)

	if metahashOutput == metahash {
		return content, nil
	} else {
		return nil, xerrors.Errorf("Content has been modified !")
	}
}

func (n *node) Comment(comment, articleID string) error {
	commentMessage := types.CommentMessage{
		ArticleID: articleID,
		UserID:    n.GetAddress(),
		Content:   comment,
		Timestamp: time.Now(),
	}

	commentTransportMessage, err := types.ToTransport(commentMessage)
	if err != nil {
		return err
	}

	return n.Broadcast(commentTransportMessage)
}

func (n *node) Vote(articleID string) error {
	pub := n.recommender.key.PublicKey
	bytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		return xerrors.Errorf("failed to marshal vote publick key: %v", err)
	}

	// z.Logger.Info().Msgf("[%s] generating proof of work for VoteMessage", n.GetAddress())
	prevStamp, thisStamp := n.getThisAndPreviousWeekStamps(time.Now())
	proof, ok := n.proofStore.Get(string(bytes), uint(thisStamp))
	// z.Logger.Info().Msgf("[%s] proof of work 1: %v", n.GetAddress(), ok)
	if !ok {
		proof, ok = n.proofStore.Get(string(bytes), uint(prevStamp))
		// z.Logger.Info().Msgf("[%s] proof of work 2: %v", n.GetAddress(), ok)
	}

	voteMessage := types.VoteMessage{
		ArticleID: articleID,
		Timestamp: time.Now(),
		Proof:     proof,
		PublicKey: bytes,
	}

	bytes, err = voteMessage.Sign(n.recommender.key)
	if err != nil {
		return xerrors.Errorf("failed to sign vote message: %v", err)
	}
	voteMessage.Signature = bytes

	voteTransportMessage, err := types.ToTransport(voteMessage)
	if err != nil {
		return err
	}

	return n.Broadcast(voteTransportMessage)
}

func (n *node) GetSummary(articleID string) types.ArticleSummaryMessage {
	return n.summaryStore.Get(articleID)
}

func (n *node) GetVoteStore() any {
	return n.voteStore
}

func (n *node) AddPublicKey(pk ecdsa.PublicKey, userID string) {
	n.pkMap[userID] = pk
}

func (n *node) Like(articleID string) error {
	n.recommender.Like(articleID)
	return n.Vote(articleID)
}

func (n *node) Dislike(articleID string) {
	n.recommender.Dislike(articleID)
}

func (n *node) GetRecommendations() []string {
	return n.recommender.GetRecommendations()
}

func (n *node) RefreshRecommendations() uint {
	return n.recommender.RefreshRecommendations()
}

func (n *node) MarkAsRead(articleID string) {
	n.recommender.MarkAsConsumed(articleID)
}
