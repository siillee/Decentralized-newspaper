package types

import "time"

type ArticleSummaryMessage struct {
	ArticleID        string
	UserID           string
	Title            string
	ShortDescription string
	Metahash         string
	Timestamp        time.Time
}

type CommentMessage struct {
	ArticleID string
	UserID    string
	Content   string
	Timestamp time.Time
}

type VoteMessage struct {
	ArticleID string
	UserID    string
	Timestamp time.Time
}
