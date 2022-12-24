package peer

import (
	"io"
)

type User interface {
	PublishArticle(title string, content io.Reader) error

	DownloadArticle(title string, conf ExpandingRing) ([]byte, error)

	Comment(comment, articleID string) error

	Vote(articleID string) error
}
