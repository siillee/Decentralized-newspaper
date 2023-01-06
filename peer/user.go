package peer

import (
	"crypto/ecdsa"
	"io"

	"go.dedis.ch/cs438/types"
)

type User interface {
	PublishArticle(title string, content io.Reader) (string, error)

	DownloadArticle(title, metahash string) ([]byte, error)

	Comment(comment, articleID string) error

	Vote(articleID string) error

	GetSummary(articleID string) types.ArticleSummaryMessage

	GetVoteStore() any // Used for testing

	AddPublicKey(pk ecdsa.PublicKey, userID string)
}
