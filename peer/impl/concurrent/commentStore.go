package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewCommentStore() CommentStore {
	comments := make(map[string][]types.CommentMessage)
	safeStore := &SafeCommentStore{
		comments: comments,
	}
	return CommentStore{safeStore}
}

type SafeCommentStore struct {
	sync.Mutex
	comments map[string][]types.CommentMessage
}

func (sf *SafeCommentStore) add(comment types.CommentMessage) {
	sf.Lock()
	defer sf.Unlock()
	sf.comments[comment.ArticleID] = append(sf.comments[comment.ArticleID], comment)
}

func (sf *SafeCommentStore) get(key string) []types.CommentMessage {
	sf.Lock()
	defer sf.Unlock()
	return sf.comments[key]
}

type CommentStore struct {
	store *SafeCommentStore
}

func (cs *CommentStore) Add(comment types.CommentMessage) {
	cs.store.add(comment)
}

func (cs *CommentStore) Get(articleID string) []types.CommentMessage {
	return cs.store.get(articleID)
}
