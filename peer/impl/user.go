package impl

import (
	"github.com/rs/xid"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"io"
	"regexp"
	"strings"
	"time"
)

func (n *node) PublishArticle(title string, content io.Reader) (string, error) {
	metaHash, err := n.Upload(content)
	if err != nil {
		return "", err
	}

	blobStore := n.conf.Storage.GetDataBlobStore()

	metafile := blobStore.Get(metaHash)
	chunkHexKeys := strings.Split(string(metafile), peer.MetafileSep)

	firstChunkData := blobStore.Get(chunkHexKeys[0])
	shortDescription := string(firstChunkData[:150])

	articleID := xid.New().String()

	articleSummaryMessage := types.ArticleSummaryMessage{
		ArticleID:        articleID,
		UserID:           n.GetAddress(),
		Title:            title,
		ShortDescription: shortDescription,
		Metahash:         metaHash,
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

	return n.Download(metahash)
}

func (n *node) Comment(comment, articleID string) error {
	commentMessage := types.CommentMessage{
		ArticleID: articleID,
		UserID:    n.GetAddress(),
		Content:   comment,
	}

	commentTransportMessage, err := types.ToTransport(commentMessage)
	if err != nil {
		return err
	}

	return n.Broadcast(commentTransportMessage)
}

func (n *node) Vote(articleID string) error {
	voteMessage := types.CommentMessage{
		ArticleID: articleID,
		UserID:    n.GetAddress(),
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
