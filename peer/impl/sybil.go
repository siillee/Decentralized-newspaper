package impl

import (
	"math/rand"
)

func NewRecommender() Recommender {
	recommendationSetSize := uint(10)
	return Recommender{
		// State args
		voteStore:  make(map[string]map[string]bool),
		trustStore: make(map[string]float64),
		consumed:   make(map[string]bool),
		current:    make([]string, 0, recommendationSetSize),
		// TODO: initialize from config object
		// Config args
		recommendationSetSize: recommendationSetSize,
		positiveFactor:        2,
		negativeFactor:        2,
		initialScore:          3,
		overwhelmingThreshold: 10,
	}
}

type Recommender struct {
	// State args
	// Article id (hash) indexed map of user id (vote id?) indexed set of votes
	voteStore map[string]map[string]bool
	// User id (vote id?) indexed map of trust values
	trustStore map[string]float64
	// Article id (hash) indexed set of already consumed articles
	consumed map[string]bool
	// Article id array of currently recommended articles
	current []string

	// Config args
	recommendationSetSize uint
	positiveFactor        float64
	negativeFactor        float64
	initialScore          float64
	overwhelmingThreshold float64
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
			r.trustStore[voter] = r.initialScore / float64(zeroCount)
		} else {
			r.trustStore[voter] *= r.positiveFactor
		}
	}
}

func (r *Recommender) Dislike(articleID string) {
	score := r.calculateArticleScore(articleID)
	for _, voter := range score.voters {
		r.trustStore[voter] *= r.negativeFactor
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
	selection := make([]string, 0, r.recommendationSetSize)
	for i := uint(0); i < r.recommendationSetSize; i++ {
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
	if uint(len(r.current)) < r.recommendationSetSize {
		return RecPartial
	}
	return RecSuccess
}

func (r *Recommender) RecordVote(articleID string, voterID string) {
	articleMap, ok := r.voteStore[articleID]
	if !ok {
		r.voteStore[articleID] = make(map[string]bool)
		articleMap = r.voteStore[articleID]
	}

	_, ok = articleMap[voterID]
	if !ok {
		// Only record vote if it has not already been recorded
		articleMap[voterID] = true
	}
}

func (r *Recommender) calculateArticleScore(articleID string) ArticleScore {
	articleMap, ok := r.voteStore[articleID]
	if !ok {
		return ArticleScore{
			id:     articleID,
			value:  0,
			voters: nil,
		}
	}

	voters := make([]string, len(articleMap))
	index := 0
	score := float64(0)
	for voterID := range articleMap {
		voters[index] = voterID
		index++

		score += r.trustStore[voterID]
	}

	return ArticleScore{
		id:     articleID,
		value:  score,
		voters: voters,
	}
}

func (r *Recommender) isOverwhelming(score *ArticleScore) bool {
	return score.value >= r.overwhelmingThreshold
}

func (r *Recommender) pickArticle() (uint, string) {
	overwhelmingArticles := make([]string, 0)
	nonOverwhelmingArticles := make([]string, 0)
	noOptions := true
	for article := range r.voteStore {
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
