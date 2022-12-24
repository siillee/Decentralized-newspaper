package concurrent

import (
	"go.dedis.ch/cs438/types"
	"sync"
)

func NewSummaryStore() SummaryStore {
	summaries := make(map[string]types.ArticleSummaryMessage)
	safeSummaryStore := &SafeSummaryStore{
		summaries: summaries,
	}
	return SummaryStore{safeSummaryStore}
}

type SafeSummaryStore struct {
	sync.Mutex
	summaries map[string]types.ArticleSummaryMessage
}

func (sf *SafeSummaryStore) set(key string, summary types.ArticleSummaryMessage) {
	sf.Lock()
	defer sf.Unlock()
	sf.summaries[key] = summary
}

func (sf *SafeSummaryStore) get(key string) types.ArticleSummaryMessage {
	sf.Lock()
	defer sf.Unlock()
	return sf.summaries[key]
}

type SummaryStore struct {
	store *SafeSummaryStore
}

func (rs *SummaryStore) Set(articleID string, summary types.ArticleSummaryMessage) {
	rs.store.set(articleID, summary)
}

func (rs *SummaryStore) Get(articleID string) types.ArticleSummaryMessage {
	return rs.store.get(articleID)
}
