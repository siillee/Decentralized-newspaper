package request

import "sync"

type DataChannels struct {
	safeMap *SafeDataMap
}

func NewDataChannels() DataChannels {
	mapping := make(map[string]chan []byte)
	safemap := &SafeDataMap{
		mapping: mapping,
	}
	return DataChannels{safemap}
}

func (dc *DataChannels) add(key string, val chan []byte) {
	dc.safeMap.add(key, val)
}

func (dc *DataChannels) get(key string) chan []byte {
	return dc.safeMap.get(key)
}

func (dc *DataChannels) del(key string) {
	dc.safeMap.del(key)
}

type SafeDataMap struct {
	sync.Mutex
	mapping map[string]chan []byte
}

func (sdm *SafeDataMap) add(key string, val chan []byte) {
	sdm.Lock()
	defer sdm.Unlock()

	sdm.mapping[key] = val
}

func (sdm *SafeDataMap) get(key string) chan []byte {
	sdm.Lock()
	defer sdm.Unlock()

	val, ok := sdm.mapping[key]
	if !ok {
		return nil
	}
	return val
}

func (sdm *SafeDataMap) del(key string) {
	sdm.Lock()
	defer sdm.Unlock()

	delete(sdm.mapping, key)
}
