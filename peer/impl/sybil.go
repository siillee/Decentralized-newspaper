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
		// log.Logger.Info().Msgf("choosing from non-overwhelming articles")
		options = nonOverwhelmingArticles
	}
	// else {
	// 	log.Logger.Info().Msgf("choosing from overwhelming articles")
	// }

	selected := options[rand.Intn(len(options))]
	r.MarkAsConsumed(selected)

	return RecSuccess, selected
}

func (n *node) proofMaintenanceLoop(keys []string) {
	// log.Logger.Info().Msgf("[%s] proofMaintenanceLoop", n.GetAddress())
	_, yearAndWeek := n.getThisAndPreviousWeekStamps(time.Now())

	shouldUpdate := n.checkIfProofsAreNeeded(keys, yearAndWeek)

	if shouldUpdate {
		n.proofUpdateLoop(keys, yearAndWeek)
	}
}

func (n *node) checkIfProofsAreNeeded(keys []string, weekstamp int) bool {
	// log.Logger.Info().Msgf("[%s] checkIfProofsAreNeeded", n.GetAddress())
	for _, key := range keys {
		_, ok := n.proofStore.Get(key, uint(weekstamp))
		if !ok {
			// log.Logger.Info().Msgf("[%s] proof missing for %v", n.GetAddress(), weekstamp)
			return true
		}
	}

	return false
}

func (n *node) proofUpdateLoop(keys []string, weekstamp int) {
	// log.Logger.Info().Msgf("[%s] proofUpdateLoop", n.GetAddress())
	seed := n.fetchUniversalRandomSeed(weekstamp)

	for _, key := range keys {
		_, ok := n.proofStore.Get(key, uint(weekstamp))
		if ok {
			// log.Logger.Info().Msgf("[%s] proof already calculated for %v", n.GetAddress(), weekstamp)
			continue
		}

		proof := n.proofCalculateInstance(key, seed)
		// log.Logger.Info().Msgf("[%s] calculated proof %v for date %v with %v zeroes", n.GetAddress(), proof, weekstamp, n.conf.ProofDifficulty)
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

func (n *node) fetchUniversalRandomSeed(weekstamp int) float64 {
	// TODO: perform api call to get some stock closing price or something like that
	seed, ok := n.seedStore.Get(weekstamp)
	if ok {
		return seed
	}

	seed = 7 // TODO: replace the "7" with api call
	n.seedStore.Add(weekstamp, seed)

	return seed
}

func (n *node) proofCalculateInstance(key string, seed float64) uint {
	// log.Logger.Info().Msgf("[%s] proofCalculateInstance", n.GetAddress())
	h := crypto.SHA256.New()
	proof := uint(0)

	for {
		valid := n.checkProof(h, key, seed, proof)
		if valid {
			return proof
		}

		proof++
	}
}

func (n *node) verifyProof(key string, timestamp time.Time, proof uint) bool {
	h := crypto.SHA256.New()

	prevYearAndWeek, thisYearAndWeek := n.getThisAndPreviousWeekStamps(timestamp)
	weekstamps := []int{prevYearAndWeek, thisYearAndWeek}

	seeds := make([]float64, len(weekstamps))
	for i, weekstamp := range weekstamps {
		seeds[i] = n.fetchUniversalRandomSeed(weekstamp)
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
	// log.Logger.Info().Msgf("[%s] number of bytes is %v for %v zeroes", n.GetAddress(), numberOfBytes, zeroesLeft)
	for i := uint(0); i < numberOfBytes; i++ {
		index := uint(len(attempt)) - 1 - i
		b := attempt[index]

		if zeroesLeft >= 8 {
			// log.Logger.Info().Msgf("[%s] check the whole byte is 0", n.GetAddress())
			// All bits have to be zero
			if b != 0 {
				return false
			}
		} else {
			// Some bits have to be zero
			mask := byte((1 << zeroesLeft) - 1)
			// log.Logger.Info().Msgf("[%s] check that %v bits are 0 with mask %v", n.GetAddress(), zeroesLeft, mask)

			if b&mask != 0 {
				return false
			}
		}
		zeroesLeft -= 8

		// if i < numberOfBytes-1 {
		// 	log.Logger.Info().Msgf("[%s] check the whole byte is 0", n.GetAddress())
		// 	// All bits have to be zero
		// 	if b != 0 {
		// 		return false
		// 	}
		// } else {
		// 	// Some (maybe all) bits have to be zero
		// 	zeroesInByte := zeroesLeft - (i+1)*8
		// 	log.Logger.Info().Msgf("[%s] check that %v bits are 0", n.GetAddress(), zeroesInByte)
		// 	mask := byte((1 << (zeroesInByte - 1)) - 1)

		// 	if b&mask != 0 {
		// 		return false
		// 	}
		// }
	}

	return true
}
