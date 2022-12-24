package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewVoteStore() VoteStore {
	votes := make(map[string][]types.VoteMessage)
	safeStore := &SafeVoteStore{
		votes: votes,
	}
	return VoteStore{safeStore}
}

type SafeVoteStore struct {
	sync.Mutex
	votes map[string][]types.VoteMessage
}

func (sf *SafeVoteStore) add(key string, rumor types.VoteMessage) {
	sf.Lock()
	defer sf.Unlock()
	sf.votes[key] = append(sf.votes[key], rumor)
}

func (sf *SafeVoteStore) get(key string) []types.VoteMessage {
	sf.Lock()
	defer sf.Unlock()
	return sf.votes[key]
}

type VoteStore struct {
	store *SafeVoteStore
}

func (vs *VoteStore) Add(articleID string, comment types.VoteMessage) {
	vs.store.add(articleID, comment)
}

func (vs *VoteStore) Get(articleID string) []types.VoteMessage {
	return vs.store.get(articleID)
}
