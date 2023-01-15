package peer

import (
	"crypto/rsa"
	"io"
	"math/big"

	"go.dedis.ch/cs438/types"
)

type User interface {
	PublishArticle(title string, content io.Reader) (string, error)

	DownloadArticle(title, metahash string) ([]byte, error)

	Comment(comment, articleID string) error

	Vote(articleID string) error

	GetSummary(articleID string) types.ArticleSummaryMessage

	GetVoteStore() any // Used for testing

	AddPublicKey(pk rsa.PublicKey, userID string)

	Like(articleID string) error

	Dislike(articleID string)

	GetRecommendations() []string

	RefreshRecommendations() uint

	MarkAsRead(articleID string)

	EstablishKeyExchange(userID string) (big.Int, error)

	GetSharedSecret(userID string) big.Int // for testing purpose
}
