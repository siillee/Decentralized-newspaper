package impl

import (
	"github.com/rs/xid"
	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
	"io"
	"regexp"
	"strings"
)

func (n *node) PublishArticle(title string, content io.Reader) error {
	metaHash, err := n.Upload(content)
	if err != nil {
		return err
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
		return err
	}

	_ = n.Tag(title, metaHash)

	return n.Broadcast(articleSummaryTransportMessage)
}

func (n *node) DownloadArticle(title string, conf peer.ExpandingRing) ([]byte, error) {
	// check if article exists locally
	reg := *regexp.MustCompile(title)
	matches := n.searchFilesLocally(reg.String())

	if len(matches) > 1 {
		z.Logger.Warn().Msgf("multiples local results for %s, should only be one result", title)
	}

	for _, metaHash := range matches {
		if n.hasAllChunks(metaHash) {
			return n.Download(metaHash) //local download
		}
	}

	// expanding ring search to find the first peer with all chunks for that article
	// Other option: Call SearchAll(*) periodically (to update catalog) and simply call Download()
	blobStore := n.conf.Storage.GetDataBlobStore()

	neighbors := n.GetNeighbors("")
	if len(neighbors) == 0 {
		return nil, nil
	}

	budget := conf.Initial
	for i := 0; i < int(conf.Retry); i++ {
		budgets := DivideBudget(budget, neighbors)
		responses := n.requestManager.SendSearchRequest(n.GetAddress(), reg.String(), neighbors, budgets, conf.Timeout)
		for j := 0; j < len(responses); j++ {
			isFullFile := true
			for _, chunk := range responses[j].Chunks {
				if len(chunk) == 0 {
					isFullFile = false
					break
				}
			}
			if isFullFile {
				for _, chunk := range responses[j].Chunks {
					chunkHash := sha256Encode(chunk)
					blobStore.Set(chunkHash, chunk)
				}
				return n.Download(responses[j].Metahash) //local download
			}
		}

		budget *= conf.Factor
	}

	return nil, nil
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
