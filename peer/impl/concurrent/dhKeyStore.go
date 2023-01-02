package concurrent

import (
	z "go.dedis.ch/cs438/logger"
	"math/big"
	"sync"
)

type DHKeyStore struct {
	safeMap *SafeKeyMap
}

func NewDHKeyStore() DHKeyStore {
	mapping := make(map[string]DHKeys)
	safemap := &SafeKeyMap{
		mapping: mapping,
	}
	return DHKeyStore{safemap}
}

// SetPrivate : Remember your own private key for that user
func (d *DHKeyStore) SetPrivate(userID string, key big.Int) {
	d.safeMap.setPrivate(userID, key)
}

// SetSharedSecret : Remember the shared secret with that user
func (d *DHKeyStore) SetSharedSecret(userID string, key big.Int) {
	d.safeMap.setShared(userID, key)
}

func (d *DHKeyStore) SetChannel(userID string, channel chan bool) {
	d.safeMap.setChannel(userID, channel)
}

func (d *DHKeyStore) Get(key string) (DHKeys, bool) {
	return d.safeMap.get(key)
}

func (d *DHKeyStore) Del(key string) {
	d.safeMap.del(key)
}

type SafeKeyMap struct {
	sync.Mutex
	mapping map[string]DHKeys
}

type DHKeys struct {
	Private       big.Int
	SharedSecret  big.Int
	NotifyChannel chan bool
}

func (skm *SafeKeyMap) setChannel(userID string, channel chan bool) {
	skm.Lock()
	defer skm.Unlock()

	entry, ok := skm.mapping[userID]
	if !ok {
		skm.mapping[userID] = DHKeys{NotifyChannel: channel}
	} else {
		entry.NotifyChannel = channel
		skm.mapping[userID] = entry
	}
}

func (skm *SafeKeyMap) setPrivate(userID string, key big.Int) {
	skm.Lock()
	defer skm.Unlock()

	entry, ok := skm.mapping[userID]
	if !ok {
		skm.mapping[userID] = DHKeys{Private: key}
	} else {
		entry.Private = key
		skm.mapping[userID] = entry
	}
}

func (skm *SafeKeyMap) setShared(userID string, key big.Int) {
	skm.Lock()
	defer skm.Unlock()

	entry, ok := skm.mapping[userID]
	if !ok {
		z.Logger.Warn().Msgf("Failed to set shared secret (no private secret stored)")
		return
	}

	entry.SharedSecret = key
	skm.mapping[userID] = entry
}

func (skm *SafeKeyMap) get(userID string) (DHKeys, bool) {
	skm.Lock()
	defer skm.Unlock()

	entry, ok := skm.mapping[userID]
	return entry, ok
}

func (skm *SafeKeyMap) del(userID string) {
	skm.Lock()
	defer skm.Unlock()

	delete(skm.mapping, userID)
}
