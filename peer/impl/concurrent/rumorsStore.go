package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewRumorsStore() RumorsStore {
	rumors := make(map[string][]types.Rumor)
	safeStore := &SafeStore{
		rumors: rumors,
	}
	return RumorsStore{safeStore}
}

type SafeStore struct {
	sync.Mutex
	rumors map[string][]types.Rumor
}

func (sf *SafeStore) add(key string, rumor types.Rumor) {
	sf.Lock()
	defer sf.Unlock()
	sf.rumors[key] = append(sf.rumors[key], rumor)
}

func (sf *SafeStore) get(key string) []types.Rumor {
	sf.Lock()
	defer sf.Unlock()
	return sf.rumors[key]
}

type RumorsStore struct {
	store *SafeStore
}

func (rs *RumorsStore) Add(key string, rumor types.Rumor) {
	rs.store.add(key, rumor)
}

func (rs *RumorsStore) Get(key string) []types.Rumor {
	return rs.store.get(key)
}
