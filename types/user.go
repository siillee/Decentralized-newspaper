package types

import (
	"fmt"
	"strings"
)

const (
	TimeFormat = "2006-01-02 15:04:05"
)

// -----------------------------------------------------------------------------
// ArticleSummaryMessage

// NewEmpty implements types.Message.
func (a ArticleSummaryMessage) NewEmpty() Message {
	return &ArticleSummaryMessage{}
}

// Name implements types.Message.
func (a ArticleSummaryMessage) Name() string {
	return "article-summary"
}

// String implements types.Message.
func (a ArticleSummaryMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "Title: \t %s \n", a.Title)
	fmt.Fprintf(out, "Description: \t %s \n", a.ShortDescription)
	fmt.Fprintf(out, "Timestamp: \t %s \n", a.Timestamp.Format(TimeFormat))

	return out.String()
}

// HTML implements types.Message.
func (a ArticleSummaryMessage) HTML() string {
	return a.String()
}

// -----------------------------------------------------------------------------
// CommentMessage

// NewEmpty implements types.Message.
func (c CommentMessage) NewEmpty() Message {
	return &CommentMessage{}
}

// Name implements types.Message.
func (c CommentMessage) Name() string {
	return "comment"
}

// String implements types.Message.
func (c CommentMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "%s - [%s] @ %s :  %s \n", c.ArticleID, c.UserID, c.Timestamp.Format(TimeFormat), c.Content)

	return out.String()
}

// HTML implements types.Message.
func (c CommentMessage) HTML() string {
	return c.String()
}

// -----------------------------------------------------------------------------
// VoteMessage

// NewEmpty implements types.Message.
func (v VoteMessage) NewEmpty() Message {
	return &VoteMessage{}
}

// Name implements types.Message.
func (v VoteMessage) Name() string {
	return "vote"
}

// String implements types.Message.
func (v VoteMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "(%s : %s) @ %s \n", v.ArticleID, v.UserID, v.Timestamp.Format(TimeFormat))

	return out.String()
}

// HTML implements types.Message.
func (v VoteMessage) HTML() string {
	return v.String()
}
