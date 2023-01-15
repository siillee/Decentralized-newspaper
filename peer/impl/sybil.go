package impl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"hash"
	"math/rand"
	"time"

	"github.com/piquette/finance-go/chart"
	"github.com/piquette/finance-go/datetime"
	log "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/concurrent"
)

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
	// Key used for VoteMessage message types (to preserve anonymity)
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

	r.MarkAsConsumed(articleID)
}

func (r *Recommender) Dislike(articleID string) {
	score := r.calculateArticleScore(articleID)
	for _, voter := range score.voters {
		r.trustStore[voter] /= r.conf.NegativeFactor
	}
	r.MarkAsConsumed(articleID)
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

func (r *Recommender) MarkAsConsumed(articleID string) {
	r.consumed[articleID] = true
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
	r.MarkAsConsumed(selected)

	return RecSuccess, selected
}

func (n *node) proofMaintenanceLoop(keys []string) {
	_, yearAndWeek := n.getThisAndPreviousWeekStamps(time.Now())

	shouldUpdate := n.checkIfProofsAreNeeded(keys, yearAndWeek)

	if shouldUpdate {
		n.proofUpdateLoop(keys, yearAndWeek)
	}
}

func (n *node) checkIfProofsAreNeeded(keys []string, weekstamp int) bool {
	for _, key := range keys {
		_, ok := n.proofStore.Get(key, uint(weekstamp))
		if !ok {
			return true
		}
	}

	return false
}

func (n *node) proofUpdateLoop(keys []string, weekstamp int) {
	seed, ok := n.fetchUniversalRandomSeed(weekstamp)
	if !ok {
		return
	}

	for _, key := range keys {
		_, ok := n.proofStore.Get(key, uint(weekstamp))
		if ok {
			continue
		}

		proof := n.proofCalculateInstance(key, seed)
		n.proofStore.Add(key, uint(weekstamp), proof)
	}
}

func (n *node) getThisAndPreviousWeekStamps(timestamp time.Time) (int, int) {
	thisYear, thisWeek := timestamp.ISOWeek()
	thisWeekStamp := thisYear*100 + thisWeek

	prevYear, prevWeek := timestamp.AddDate(0, 0, -7).ISOWeek()
	prevWeekStamp := prevYear*100 + prevWeek

	return prevWeekStamp, thisWeekStamp
}

func (n *node) fetchUniversalRandomSeed(weekstamp int) (float64, bool) {
	// Return from seed store if seed was used before
	seed, ok := n.seedStore.Get(weekstamp)
	if ok {
		return seed, true
	}

	// Set up api call to get MSFT closing price for Friday before week from weekstamp
	friday := n.getLastFridayFromWeekStamp(weekstamp)
	saturday := friday.AddDate(0, 0, 1)
	params := &chart.Params{
		Symbol:   "MSFT",
		Start:    datetime.FromUnix(int(friday.Unix())),
		End:      datetime.FromUnix(int(saturday.Unix())),
		Interval: datetime.OneDay,
	}

	// Make api call
	iter := chart.Get(params)

	// Extract the closing price from the response
	iter.Next()
	seed = iter.Bar().Close.InexactFloat64()

	// Check for errors
	err := iter.Err()
	if err != nil {
		log.Logger.Err(err).Msgf("[%s] failed fetching random seed from stock market", n.GetAddress())
		return 0, false
	}

	// Remember seed for future usage
	n.seedStore.Add(weekstamp, seed)

	return seed, true
}

func (n *node) getLastFridayFromWeekStamp(weekstamp int) time.Time {
	year := weekstamp / 100
	week := weekstamp % 100

	// Jump to a day in the ISO year/week combination
	curr := time.Date(year, 0, 0, 0, 0, 0, 0, time.UTC)
	currYear, currWeek := curr.ISOWeek()
	for currYear < year || (currYear == year && currWeek < week) {
		curr = curr.AddDate(0, 0, 7)
		currYear, currWeek = curr.ISOWeek()
	}
	for currYear > year || (currYear == year && currWeek > week) {
		curr = curr.AddDate(0, 0, -7)
		currYear, currWeek = curr.ISOWeek()
	}

	// Jump to the Monday of that week
	for curr.Weekday() != time.Monday {
		curr = curr.AddDate(0, 0, -1)
	}

	// Jump to the Friday of last week
	curr = curr.AddDate(0, 0, -3)

	// log.Logger.Info().Msgf("[%s] got date %v/%v/%v from weekstamp %v", n.GetAddress(), curr.Day(), curr.Month(), curr.Year(), weekstamp)
	return curr
}

func (n *node) proofCalculateInstance(key string, seed float64) uint {
	h := crypto.SHA256.New()
	proof := uint(0)

	for {
		valid := n.checkProof(h, key, seed, proof)
		if valid {
			return proof
		}

		proof++

		// This task might be long, check if node is still running
		if proof%1_000_000 == 0 {
			if !n.isOpen() {
				return 0
			}
		}
	}
}

func (n *node) verifyProof(key string, timestamp time.Time, proof uint) bool {
	h := crypto.SHA256.New()

	prevYearAndWeek, thisYearAndWeek := n.getThisAndPreviousWeekStamps(timestamp)
	weekstamps := []int{prevYearAndWeek, thisYearAndWeek}

	seeds := make([]float64, len(weekstamps))
	for i, weekstamp := range weekstamps {
		seed, ok := n.fetchUniversalRandomSeed(weekstamp)
		if !ok {
			return false
		}

		seeds[i] = seed
	}

	for _, seed := range seeds {
		if n.checkProof(h, key, seed, proof) {
			return true
		}
	}
	return false
}

func (n *node) checkProof(h hash.Hash, key string, seed float64, proof uint) bool {
	h.Reset()
	h.Write([]byte(key))
	h.Write([]byte(fmt.Sprint(seed)))
	h.Write([]byte(fmt.Sprint(proof)))
	attempt := h.Sum(nil)

	zeroesLeft := n.conf.ProofDifficulty
	numberOfBytes := (zeroesLeft + 7) / 8
	for i := uint(0); i < numberOfBytes; i++ {
		index := uint(len(attempt)) - 1 - i
		b := attempt[index]

		if zeroesLeft >= 8 {
			// All bits have to be zero
			if b != 0 {
				return false
			}
		} else {
			// Some bits have to be zero
			mask := byte((1 << zeroesLeft) - 1)

			if b&mask != 0 {
				return false
			}
		}
		zeroesLeft -= 8
	}

	return true
}
