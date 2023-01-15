package concurrent

import (
	"sync"
)

func NewProofStore() ProofStore {
	safeStore := &SafeProofStore{
		proofs: make(map[string]map[uint]uint),
	}
	return ProofStore{safeStore}
}

type SafeProofStore struct {
	sync.Mutex
	proofs map[string]map[uint]uint
}

func (sf *SafeProofStore) add(key string, date uint, proof uint) {
	sf.Lock()
	defer sf.Unlock()

	_, ok := sf.proofs[key]
	if !ok {
		sf.proofs[key] = make(map[uint]uint)
	}

	sf.proofs[key][date] = proof
}

func (sf *SafeProofStore) get(key string, date uint) (uint, bool) {
	sf.Lock()
	defer sf.Unlock()

	_, ok := sf.proofs[key]
	if !ok {
		return 0, false
	}

	proof, ok := sf.proofs[key][date]
	return proof, ok
}

func (sf *SafeProofStore) remove(key string, date uint) {
	sf.Lock()
	defer sf.Unlock()

	_, ok := sf.proofs[key]
	if !ok {
		return
	}

	delete(sf.proofs[key], date)
}

type ProofStore struct {
	store *SafeProofStore
}

func (ps *ProofStore) Add(key string, date uint, proof uint) {
	ps.store.add(key, date, proof)
}

func (ps *ProofStore) Get(key string, date uint) (uint, bool) {
	return ps.store.get(key, date)
}

func (ps *ProofStore) Remove(key string, date uint) {
	ps.store.remove(key, date)
}
