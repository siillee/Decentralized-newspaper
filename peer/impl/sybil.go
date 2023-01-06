package impl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"math/rand"

	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/concurrent"
)

func (n *node) Like(articleID string) error {
	n.recommender.Like(articleID)
	return n.Vote(articleID)
}

func (n *node) Dislike(articleID string) {
	n.recommender.Dislike(articleID)
}

func (n *node) GetRecommendations() []string {
	return n.recommender.GetRecommendations()
}

func (n *node) RefreshRecommendations() uint {
	return n.recommender.RefreshRecommendations()
}

func NewRecommender(conf *peer.Configuration, voteStore *concurrent.VoteStore) Recommender {
	EC := elliptic.P256()
	key, _ := ecdsa.GenerateKey(EC, crand.Reader) // TODO: error?

	return Recommender{
		// Config args
		conf: conf,
		// State args
		voteStore:  voteStore,
		trustStore: make(map[string]float64),
		consumed:   make(map[string]bool),
		current:    make([]string, 0, conf.RecommendationSetSize),
		key:        key,
	}
}

type Recommender struct {
	// Config
	conf *peer.Configuration
	// State args
	// Article id (hash) indexed map of user id (vote id?) indexed set of votes
	voteStore *concurrent.VoteStore
	// User id (vote id?) indexed map of trust values
	trustStore map[string]float64
	// Article id (hash) indexed set of already consumed articles
	consumed map[string]bool
	// Article id array of currently recommended articles
	current []string
	// Key?
	key *ecdsa.PrivateKey
}

type ArticleScore struct {
	id     string
	value  float64
	voters []string
}

func (r *Recommender) Like(articleID string) {
	score := r.calculateArticleScore(articleID)
	if r.isOverwhelming(&score) {
		// skip - do not increase trust for voters since Alice is already getting "enough help"
		return
	}

	// Count zero trust voters
	zeroCount := 0
	for _, voter := range score.voters {
		if r.trustStore[voter] == 0 {
			zeroCount++
		}
	}

	// Update trust values
	for _, voter := range score.voters {
		if r.trustStore[voter] == 0 {
			r.trustStore[voter] = r.conf.InitialScore / float64(zeroCount)
		} else {
			r.trustStore[voter] *= r.conf.PositiveFactor
		}
	}
}

func (r *Recommender) Dislike(articleID string) {
	score := r.calculateArticleScore(articleID)
	for _, voter := range score.voters {
		r.trustStore[voter] *= r.conf.NegativeFactor
	}
}

func (r *Recommender) GetRecommendations() []string {
	return r.current
}

const (
	RecFailure uint = iota
	RecPartial
	RecSuccess
)

func (r *Recommender) RefreshRecommendations() uint {
	selection := make([]string, 0, r.conf.RecommendationSetSize)
	for i := uint(0); i < r.conf.RecommendationSetSize; i++ {
		recStatus, selected := r.pickArticle()
		if recStatus == RecFailure {
			break
		}

		selection = append(selection, selected)
	}
	r.current = selection

	if len(r.current) == 0 {
		return RecFailure
	}
	if uint(len(r.current)) < r.conf.RecommendationSetSize {
		return RecPartial
	}
	return RecSuccess
}

func (r *Recommender) calculateArticleScore(articleID string) ArticleScore {
	voters := r.voteStore.Get(articleID)
	score := float64(0)
	for _, voterID := range voters {
		score += r.trustStore[voterID]
	}

	return ArticleScore{
		id:     articleID,
		value:  score,
		voters: voters,
	}
}

func (r *Recommender) isOverwhelming(score *ArticleScore) bool {
	return score.value >= r.conf.OverwhelmingThreshold
}

func (r *Recommender) pickArticle() (uint, string) {
	overwhelmingArticles := make([]string, 0)
	nonOverwhelmingArticles := make([]string, 0)
	noOptions := true
	for _, article := range r.voteStore.GetArticles() {
		_, ok := r.consumed[article]
		if ok {
			continue
		}
		noOptions = false

		score := r.calculateArticleScore(article)
		if r.isOverwhelming(&score) {
			overwhelmingArticles = append(overwhelmingArticles, article)
		} else {
			nonOverwhelmingArticles = append(nonOverwhelmingArticles, article)
		}
	}

	if noOptions {
		return RecFailure, ""
	}

	options := overwhelmingArticles
	if len(overwhelmingArticles) == 0 {
		options = nonOverwhelmingArticles
	}

	selected := options[rand.Intn(len(options))]
	r.consumed[selected] = true

	return RecSuccess, selected
}
