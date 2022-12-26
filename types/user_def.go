package types

type ArticleSummaryMessage struct {
	ArticleID string
	UserID    string
	Title     string
	//ShortDescription string (input from user or use first lines of article ? What if we allow article to be pdf (or other file format) ?)
	Metahash string
	//date timestamp
	Signature []byte
	// TODO add signature of content
}

type CommentMessage struct {
	ArticleID string
	UserID    string
	Content   string
	//date timestamp
	Signature []byte
}

type VoteMessage struct {
	ArticleID string
	UserID    string
	Signature []byte
}
