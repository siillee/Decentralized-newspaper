package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewVoteStore() VoteStore {
	votes := make(map[string]map[string]struct{})
	safeStore := &SafeVoteStore{
		votes: votes,
	}
	return VoteStore{safeStore}
}

type SafeVoteStore struct {
	sync.Mutex
	votes map[string]map[string]struct{} //articleID -> Set() (avoid duplicates)
}

func (sf *SafeVoteStore) add(vote types.VoteMessage) {
	sf.Lock()
	defer sf.Unlock()
	_, ok := sf.votes[vote.ArticleID]
	if ok {
		sf.votes[vote.ArticleID][vote.UserID] = struct{}{}
	} else {
		sf.votes[vote.ArticleID] = make(map[string]struct{})
		sf.votes[vote.ArticleID][vote.UserID] = struct{}{}
	}
}

func (sf *SafeVoteStore) get(key string) map[string]struct{} {
	sf.Lock()
	defer sf.Unlock()
	return sf.votes[key]
}

type VoteStore struct {
	store *SafeVoteStore
}

func (vs *VoteStore) Add(vote types.VoteMessage) {
	vs.store.add(vote)
}

func (vs *VoteStore) Get(articleID string) []string {
	var users []string
	mapping := vs.store.get(articleID)
	for k, _ := range mapping {
		users = append(users, k)
	}
	return users
}
