package concurrent

import "sync"

type AckChannels struct {
	safeMap *SafeAckMap
}

func NewAckChannels() AckChannels {
	mapping := make(map[string]chan bool)
	safemap := &SafeAckMap{
		mapping: mapping,
	}
	return AckChannels{safemap}
}

func (ac *AckChannels) Add(key string, val chan bool) {
	ac.safeMap.add(key, val)
}

func (ac *AckChannels) Get(key string) chan bool {
	return ac.safeMap.get(key)
}

func (ac *AckChannels) Del(key string) {
	ac.safeMap.del(key)
}

type SafeAckMap struct {
	sync.Mutex
	mapping map[string]chan bool
}

func (sam *SafeAckMap) add(key string, val chan bool) {
	sam.Lock()
	defer sam.Unlock()

	sam.mapping[key] = val
}

func (sam *SafeAckMap) get(key string) chan bool {
	sam.Lock()
	defer sam.Unlock()

	val, ok := sam.mapping[key]
	if !ok {
		return nil
	}
	return val
}

func (sam *SafeAckMap) del(key string) {
	sam.Lock()
	defer sam.Unlock()

	delete(sam.mapping, key)
}
