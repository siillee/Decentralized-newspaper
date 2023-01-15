package concurrent

import (
	"sync"
)

func NewSeedStore() SeedStore {
	return SeedStore{
		store: &SeedSafeStore{
			seeds: make(map[int]float64),
		},
	}
}

type SeedSafeStore struct {
	sync.Mutex
	seeds map[int]float64
}

func (sf *SeedSafeStore) add(key int, seed float64) {
	sf.Lock()
	defer sf.Unlock()
	sf.seeds[key] = seed
}

func (sf *SeedSafeStore) get(key int) (float64, bool) {
	sf.Lock()
	defer sf.Unlock()
	seed, ok := sf.seeds[key]
	return seed, ok
}

type SeedStore struct {
	store *SeedSafeStore
}

func (ss *SeedStore) Add(key int, seed float64) {
	ss.store.add(key, seed)
}

func (ss *SeedStore) Get(key int) (float64, bool) {
	return ss.store.get(key)
}
