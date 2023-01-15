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
	from  time.Time
	until time.Time
	valid bool
	votes map[string]time.Time // set of user IDs (or aliases) (avoid duplicates)
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
		// Only record vote if it has been made after the article has been made, but before the voting timeout (or if voting timeout is zero)
		if vote.Timestamp.After(articleVoteStore.from) && (articleVoteStore.until.IsZero() || vote.Timestamp.Before(articleVoteStore.until)) {
			articleVoteStore.votes[string(vote.PublicKey)] = vote.Timestamp
		}
	} else {
		sf.votes[vote.ArticleID] = ArticleVoteStore{
			from:  time.Time{}, // the zero value
			until: time.Time{}, // the zero value
			valid: false,
			votes: make(map[string]time.Time),
		}
		sf.votes[vote.ArticleID].votes[string(vote.PublicKey)] = vote.Timestamp
	}
}

func (sf *SafeVoteStore) register(articleID string, voteFrom time.Time, voteUntil time.Time) {
	sf.Lock()
	defer sf.Unlock()
	articleVoteStore, ok := sf.votes[articleID]
	if ok {
		articleVoteStore.from = voteFrom
		articleVoteStore.until = voteUntil
		articleVoteStore.valid = true

		// Filter out early votes (spam)
		{
			validVotes := make(map[string]time.Time)

			for voteKey, voteTimestamp := range articleVoteStore.votes {
				if voteTimestamp.After(voteFrom) {
					validVotes[voteKey] = voteTimestamp
				}
			}
			articleVoteStore.votes = validVotes
		}

		// Filter out late votes
		if !voteUntil.IsZero() {
			// Trim votes that have not been made before the voting timeout
			validVotes := make(map[string]time.Time)

			for voteKey, voteTimestamp := range articleVoteStore.votes {
				if voteTimestamp.Before(voteUntil) {
					validVotes[voteKey] = voteTimestamp
				}
			}
			articleVoteStore.votes = validVotes
		}

		sf.votes[articleID] = articleVoteStore
	} else {
		sf.votes[articleID] = ArticleVoteStore{
			from:  voteFrom,
			until: voteUntil,
			valid: true,
			votes: make(map[string]time.Time),
		}
	}
}

func (sf *SafeVoteStore) get(key string) map[string]time.Time {
	sf.Lock()
	defer sf.Unlock()

	copy := make(map[string]time.Time)
	for k, v := range sf.votes[key].votes {
		copy[k] = v
	}

	return copy
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

func (vs *VoteStore) Register(articleID string, voteFrom time.Time, voteUntil time.Time) {
	vs.store.register(articleID, voteFrom, voteUntil)
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
