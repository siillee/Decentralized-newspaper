package types

type ArticleSummaryMessage struct {
	ArticleID        string
	UserID           string
	Title            string
	ShortDescription string
	Metahash         string
	//date timestamp
}

type CommentMessage struct {
	ArticleID string
	UserID    string
	Content   string
	//date timestamp
}

type VoteMessage struct {
	ArticleID string
	UserID    string
}
