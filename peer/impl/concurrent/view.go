package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewView() View {
	view := make(types.StatusMessage)
	safeView := &SafeView{
		statusMessage: view,
	}
	return View{safeView}
}

type SafeView struct {
	sync.Mutex
	statusMessage types.StatusMessage
}

func (sv *SafeView) set(key string, val uint) {
	sv.Lock()
	defer sv.Unlock()
	sv.statusMessage[key] = val
}

func (sv *SafeView) get(key string) (uint, bool) {
	sv.Lock()
	defer sv.Unlock()
	seq, ok := sv.statusMessage[key]
	return seq, ok
}

type View struct {
	view *SafeView
}

func (cv *View) Set(key string, seq uint) {
	cv.view.set(key, seq)
}

func (cv *View) GetEntry(key string) (uint, bool) {
	return cv.view.get(key)
}

func (cv *View) Copy() types.StatusMessage {
	copyTable := make(map[string]uint)
	cv.view.Lock()
	for key, value := range cv.view.statusMessage {
		copyTable[key] = value
	}
	cv.view.Unlock()
	return copyTable
}
