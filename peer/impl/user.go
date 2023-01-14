package impl

import (
	"bytes"
	"crypto/rsa"
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

	if n.conf.TorEnabled {
		buf := new(bytes.Buffer)
		buf.ReadFrom(content)
		return articleID, n.AnonymousPublishArticle(articleSummaryMessage, buf.String())
	}

	//add signature only if not anonymous and if it has a privateKey
	if n.conf.PrivateKey != nil {
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

	if n.conf.TorEnabled {
		return n.AnonymousDownloadArticle(title, metahash)
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
	voteMessage := types.VoteMessage{
		ArticleID: articleID,
		UserID:    n.GetAddress(),
		Timestamp: time.Now(),
	}

	voteTransportMessage, err := types.ToTransport(voteMessage)
	if err != nil {
		return err
	}

	return n.Broadcast(voteTransportMessage)
}

func (n *node) GetSummary(articleID string) types.ArticleSummaryMessage {
	return n.summaryStore.Get(articleID)
}

func (n *node) AddPublicKey(pk rsa.PublicKey, userID string) {
	n.pkMap[userID] = pk
}
