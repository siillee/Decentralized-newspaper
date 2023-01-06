package concurrent

import (
	"sync"
	"time"

	"go.dedis.ch/cs438/types"
)

func NewVoteStore() VoteStore {
	votes := make(map[string]ArticleVoteStore)
	safeStore := &SafeVoteStore{
		votes: votes,
	}
	return VoteStore{safeStore}
}

type ArticleVoteStore struct {
	timestamp time.Time
	valid     bool
	votes     map[string]time.Time // set of user IDs (or aliases) (avoid duplicates)
}

type SafeVoteStore struct {
	sync.Mutex
	votes map[string]ArticleVoteStore
}

func (sf *SafeVoteStore) add(vote types.VoteMessage) {
	sf.Lock()
	defer sf.Unlock()
	articleVoteStore, ok := sf.votes[vote.ArticleID]
	if ok {
		// Only record vote if voteTimeout is zero or if vote timestamp is before the voteTimeout
		if articleVoteStore.timestamp.IsZero() || vote.Timestamp.Before(articleVoteStore.timestamp) {
			articleVoteStore.votes[string(vote.PublicKey)] = vote.Timestamp
		}
	} else {
		sf.votes[vote.ArticleID] = ArticleVoteStore{
			timestamp: time.Time{}, // the zero value
			valid:     false,
			votes:     make(map[string]time.Time),
		}
		sf.votes[vote.ArticleID].votes[string(vote.PublicKey)] = vote.Timestamp
	}
}

func (sf *SafeVoteStore) register(articleID string, voteTimeout time.Time) {
	sf.Lock()
	defer sf.Unlock()
	articleVoteStore, ok := sf.votes[articleID]
	if ok {
		articleVoteStore.timestamp = voteTimeout
		articleVoteStore.valid = true

		if !voteTimeout.IsZero() {
			// Trim votes that have not been made before the voteTimeout
			validVotes := make(map[string]time.Time)

			for voteKey, voteTimestamp := range articleVoteStore.votes {
				if voteTimestamp.Before(voteTimeout) {
					validVotes[voteKey] = voteTimestamp
				}
			}
			articleVoteStore.votes = validVotes
		}

		sf.votes[articleID] = articleVoteStore
	} else {
		sf.votes[articleID] = ArticleVoteStore{
			timestamp: voteTimeout,
			valid:     true,
			votes:     make(map[string]time.Time),
		}
	}
}

func (sf *SafeVoteStore) get(key string) map[string]time.Time {
	sf.Lock()
	defer sf.Unlock()
	return sf.votes[key].votes
}

func (sf *SafeVoteStore) getArticles() []string {
	sf.Lock()
	defer sf.Unlock()
	articles := make([]string, 0)
	for articleID, store := range sf.votes {
		if store.valid {
			articles = append(articles, articleID)
		}
	}
	return articles
}

type VoteStore struct {
	store *SafeVoteStore
}

func (vs *VoteStore) Add(vote types.VoteMessage) {
	vs.store.add(vote)
}

func (vs *VoteStore) Register(articleID string, voteTimeout time.Time) {
	vs.store.register(articleID, voteTimeout)
}

func (vs *VoteStore) Get(articleID string) []string {
	var users []string
	mapping := vs.store.get(articleID)
	for k := range mapping {
		users = append(users, k)
	}
	return users
}

func (vs *VoteStore) GetArticles() []string {
	return vs.store.getArticles()
}
