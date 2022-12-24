package request

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

type SearchChannels struct {
	safeMap *SafeSearchMap
}

func NewSearchChannels() SearchChannels {
	mapping := make(map[string]chan types.FileInfo)
	safemap := &SafeSearchMap{
		mapping: mapping,
	}
	return SearchChannels{safemap}
}

func (sc *SearchChannels) add(key string, val chan types.FileInfo) {
	sc.safeMap.add(key, val)
}

func (sc *SearchChannels) get(key string) chan types.FileInfo {
	return sc.safeMap.get(key)
}

func (sc *SearchChannels) del(key string) {
	sc.safeMap.del(key)
}

type SafeSearchMap struct {
	sync.Mutex
	mapping map[string]chan types.FileInfo
}

func (sfm *SafeSearchMap) add(key string, val chan types.FileInfo) {
	sfm.Lock()
	defer sfm.Unlock()

	sfm.mapping[key] = val
}

func (sfm *SafeSearchMap) get(key string) chan types.FileInfo {
	sfm.Lock()
	defer sfm.Unlock()

	val, ok := sfm.mapping[key]
	if !ok {
		return nil
	}
	return val
}

func (sfm *SafeSearchMap) del(key string) {
	sfm.Lock()
	defer sfm.Unlock()

	delete(sfm.mapping, key)
}
