package peer

import (
	"crypto/ecdsa"
	"go.dedis.ch/cs438/types"
	"io"
	"math/big"
)

type User interface {
	PublishArticle(title string, content io.Reader) (string, error)

	DownloadArticle(title, metahash string) ([]byte, error)

	Comment(comment, articleID string) error

	Vote(articleID string) error

	GetSummary(articleID string) types.ArticleSummaryMessage

	AddPublicKey(pk ecdsa.PublicKey, userID string)

	EstablishKeyExchange(userID string) (big.Int, error)

	GetSharedSecret(userID string) big.Int // for testing purpose
}
