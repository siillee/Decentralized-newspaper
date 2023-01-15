package impl

import (
	"crypto/rsa"
	"crypto/x509"
	"math/rand"
	"sort"
	"sync"
	"time"

	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/peer/impl/concurrent"
	"go.dedis.ch/cs438/request"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

// NewPeer creates a new peer. You can change the content and location of this
// function, but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	routingTable := concurrent.NewRoutingTable()
	view := concurrent.NewView()
	rumorsStore := concurrent.NewRumorsStore()
	summaryStore := concurrent.NewSummaryStore()
	voteStore := concurrent.NewVoteStore()
	commentStore := concurrent.NewCommentStore()
	proofStore := concurrent.NewProofStore()
	seedStore := concurrent.NewSeedStore()
	ackChannels := concurrent.NewAckChannels()

	// the peer's routing table should contain one element, the peer’s address and relay to itself
	peerAddress := conf.Socket.GetAddress()
	routingTable.AddEntry(peerAddress, peerAddress)

	// mapping between peer address (or userID) and their public key
	pkMap := make(map[string]rsa.PublicKey)
	if conf.PrivateKey != nil {
		pkMap[peerAddress] = conf.PrivateKey.PublicKey
	}

	catalog := make(peer.Catalog)
	recommender := NewRecommender(&conf, &voteStore)

	n := &node{
		conf:                           conf,
		open:                           false,
		routingTable:                   routingTable,
		currentSequenceNumber:          0,
		view:                           view,
		ackChannels:                    ackChannels,
		rumorsStore:                    rumorsStore,
		summaryStore:                   summaryStore,
		commentStore:                   commentStore,
		proofStore:                     proofStore,
		seedStore:                      seedStore,
		voteStore:                      voteStore,
		catalog:                        catalog,
		pkMap:                          pkMap,
		recommender:                    recommender,
		directory:                      types.Directory{Dir: make(map[string]*rsa.PublicKey)},
		proxyCircuits:                  types.ConcurrentProxyCircuits{ProxyCircuits: make(map[string]*types.ProxyCircuit)},
		relayCircuits:                  types.ConcurrentRelayCircuits{RelayCircuits: make(map[string]*types.RelayCircuit)},
		keyExchangeReplyChannels:       types.KeyExchangeReplyChannels{ChannelMap: make(map[string]chan types.KeyExchangeReplyMessage)},
		anonymousDownloadReplyChannels: types.AnonymousDownloadReplyChannels{ChannelMap: make(map[string]chan types.AnonymousDownloadReplyMessage)},
	}

	n.requestManager = request.NewRequestManager(n, n.conf.BackoffDataRequest)

	for _, dirNode := range n.conf.DirectoryNodes {
		n.AddPeer(dirNode)
	}

	return n
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	sync.Mutex
	conf                           peer.Configuration
	open                           bool
	routingTable                   concurrent.RoutingTable
	currentSequenceNumber          uint
	view                           concurrent.View
	ackChannels                    concurrent.AckChannels
	rumorsStore                    concurrent.RumorsStore
	summaryStore                   concurrent.SummaryStore
	voteStore                      concurrent.VoteStore
	commentStore                   concurrent.CommentStore
	proofStore                     concurrent.ProofStore
	seedStore                      concurrent.SeedStore
	catalog                        peer.Catalog
	requestManager                 request.Manager
	pkMap                          map[string]rsa.PublicKey
	recommender                    Recommender
	directory                      types.Directory
	proxyCircuits                  types.ConcurrentProxyCircuits
	relayCircuits                  types.ConcurrentRelayCircuits
	keyExchangeReplyChannels       types.KeyExchangeReplyChannels
	anonymousDownloadReplyChannels types.AnonymousDownloadReplyChannels
}

func (n *node) GetNeighbors(excluded string) []string {
	copyTable := n.routingTable.Copy()
	neighbors := make(map[string]struct{}) //use map to avoid duplicates
	for _, value := range copyTable {
		if value != n.GetAddress() && value != excluded {
			neighbors[value] = struct{}{}
		}
	}
	neighborsTable := make([]string, 0, len(neighbors))
	for k := range neighbors {
		neighborsTable = append(neighborsTable, k)
	}
	return neighborsTable
}

func (n *node) GetRandomNeighbor(excluded string) string {
	neighbors := n.GetNeighbors(excluded)
	if len(neighbors) > 0 {
		return neighbors[rand.Intn(len(neighbors))]
	}
	return ""
}

// -----------------------------------------------------------------------------
// Handler functions

func (n *node) ExecChatMessage(msg types.Message, pkt transport.Packet) error {
	_, ok := msg.(*types.ChatMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] chat message received from %s", n.GetAddress(), pkt.Header.Source)
	// z.Logger.Info().Msgf("[%s] %s", n.GetAddress(), chatMsg)

	return nil
}

func (n *node) ExecRumorsMessage(msg types.Message, pkt transport.Packet) error {
	// z.Logger.Info().Msgf("[%s] ExecRumorsMessage in", n.GetAddress())
	rumorsMsg, ok := msg.(*types.RumorsMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] rumors Message received from %s", n.GetAddress(), pkt.Header.Source)

	rumorsHaveBeenRelayed := false
	for _, rumor := range rumorsMsg.Rumors {
		currentOriginSeq, _ := n.view.GetEntry(rumor.Origin)
		isRumorExpected := rumor.Sequence == currentOriginSeq+1

		if !isRumorExpected {
			continue
		}

		//update routing entry
		_, ok = n.routingTable.GetEntry(rumor.Origin)
		if !ok {
			n.SetRoutingEntry(rumor.Origin, pkt.Header.RelayedBy)
		}

		//update peer's view and store this rumor
		n.view.Set(rumor.Origin, rumor.Sequence)
		n.rumorsStore.Add(rumor.Origin, rumor)

		//process rumor locally
		localPkt := transport.Packet{Header: pkt.Header, Msg: rumor.Msg}
		err := n.conf.MessageRegistry.ProcessPacket(localPkt)
		if err != nil {
			return xerrors.Errorf(
				"[%s] failed to process rumor %u from %s : %v", n.GetAddress(), rumor.Sequence, rumor.Origin, err,
			)
		}

		//send RumorsMessage to another random neighbor (only once)
		if rumorsHaveBeenRelayed {
			continue
		}

		neighbor := n.GetRandomNeighbor(pkt.Header.Source)
		if neighbor == "" {
			// z.Logger.Debug().Msgf(
			// 	"[%s] no neighbor found (expected rumor but unable to relay it to a random neighbor", n.GetAddress(),
			// )
			continue
		}

		rumorsTransportMessage, err1 := types.ToTransport(rumorsMsg)
		if err1 != nil {
			return xerrors.Errorf("[%s] failed to build rumors transport message : %v", n.GetAddress(), err)
		}

		newPkt, err1 := n.SendTo(neighbor, rumorsTransportMessage)
		// z.Logger.Info().Msgf("[%s] relay rumors message to %s", n.GetAddress(), neighbor)
		if err1 != nil {
			return xerrors.Errorf("[%s] failed to send rumors message to %s : %v", n.GetAddress(), neighbor, err)
		}
		rumorsHaveBeenRelayed = true

		go n.WaitForAck(newPkt, neighbor, rumorsTransportMessage)
	}
	// z.Logger.Info().Msgf("[%s] ExecRumorsMessage loop left", n.GetAddress())

	ackMessage := types.AckMessage{AckedPacketID: pkt.Header.PacketID, Status: n.view.Copy()}
	ackTransportMessage, err := types.ToTransport(ackMessage)
	if err != nil {
		// z.Logger.Info().Msgf("[%s] ExecRumorsMessage out", n.GetAddress())
		return xerrors.Errorf("[%s] failed to send ack to %s: %v", n.GetAddress(), pkt.Header.Source, err)
	}

	// z.Logger.Info().Msgf("[%s] ExecRumorsMessage finna send ack", n.GetAddress())
	_, err = n.SendTo(pkt.Header.Source, ackTransportMessage)
	// z.Logger.Info().Msgf("[%s] ExecRumorsMessage did send ack (or error)", n.GetAddress())
	// z.Logger.Info().Msgf("[%s] send ack (id: %s) to %s", n.GetAddress(), pkt.Header.PacketID, pkt.Header.Source)
	if err != nil {
		// z.Logger.Info().Msgf("[%s] ExecRumorsMessage out", n.GetAddress())
		return xerrors.Errorf("[%s] failed to send ack to %s: %v", n.GetAddress(), pkt.Header.Source, err)
	}

	// z.Logger.Info().Msgf("[%s] ExecRumorsMessage out", n.GetAddress())
	return nil
}

func (n *node) ExecAckMessage(msg types.Message, pkt transport.Packet) error {
	ackMsg, ok := msg.(*types.AckMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf(
	// 	"[%s] ack Message received from %s with ackId %s:", n.GetAddress(), pkt.Header.Source, ackMsg.AckedPacketID,
	// )

	statusTransportMessage, err := types.ToTransport(ackMsg.Status)
	if err != nil {
		return xerrors.Errorf("[%s] failed to build status transport message from ack : %v", n.GetAddress(), err)
	}

	// Process status message locally
	pkt.Msg = &statusTransportMessage
	err = n.conf.MessageRegistry.ProcessPacket(pkt)
	if err != nil {
		return xerrors.Errorf("[%s] failed to process ack message : %v", n.GetAddress(), err)
	}

	ch := n.ackChannels.Get(ackMsg.AckedPacketID)
	if ch != nil {
		ch <- true
	}

	return err
}

func (n *node) ExecStatusMessage(msg types.Message, pkt transport.Packet) error {
	statusMessage, ok := msg.(*types.StatusMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] status Message received from %s: ", n.GetAddress(), pkt.Header.Source)
	// z.Logger.Info().Msgf("[%s] %s", n.GetAddress(), statusMessage.String())

	// case1: The remote peer has Rumors that this peer doesn’t have.
	case1, err := n.checkCase1(pkt, statusMessage)
	if err != nil {
		return xerrors.Errorf("[%s] failed to check case 1: %v", n.GetAddress(), err)
	}

	// case2: This peer has Rumors that the remote peer doesn’t have.
	case2, err := n.checkCase2(pkt, statusMessage)
	// z.Logger.Info().Msgf("[%s] checkCase2 over and out", n.GetAddress())
	if err != nil {
		return xerrors.Errorf("[%s] failed to check case 2: %v", n.GetAddress(), err)
	}

	// case4: Both peers have the same view, send status message to a random neighbor
	// with probability n.conf.ContinueMongering .
	if !case1 && !case2 && rand.Float64() <= n.conf.ContinueMongering {
		neighbor := n.GetRandomNeighbor(pkt.Header.Source)
		if neighbor == "" {
			return nil
		}
		statusTransportMessage, err1 := types.ToTransport(n.view.Copy())
		if err1 != nil {
			return xerrors.Errorf("[%s] failed to build status transport message : %v", n.GetAddress(), err)
		}

		// z.Logger.Debug().Msgf(
		// 	"[%s] case4: both peers have the same view, continue mongering, sending status message to %s",
		// 	n.GetAddress(), neighbor,
		// )
		_, err = n.SendTo(neighbor, statusTransportMessage)
		if err != nil {
			return xerrors.Errorf(
				"[%s], failed to send status message to random neighbor %s : %v",
				n.GetAddress(), neighbor, err,
			)
		}
	}
	return nil
}

func (n *node) checkCase1(pkt transport.Packet, statusMessage *types.StatusMessage) (bool, error) {
	for key, remoteValue := range statusMessage.View() {
		localValue, ok1 := n.view.GetEntry(key)
		if !ok1 || remoteValue > localValue {
			// z.Logger.Debug().Msgf(
			// 	"[%s] case1: the remote peer (%s) has Rumors that this peer doesn’t have (key:%s)",
			// 	n.GetAddress(), pkt.Header.Source, key,
			// )

			statusTransportMessage, err := types.ToTransport(n.view.Copy())
			if err != nil {
				return false, xerrors.Errorf("[%s] failed to build status transport message : %v", n.GetAddress(), err)
			}

			// z.Logger.Debug().Msgf("[%s] send status message back to %s", n.GetAddress(), pkt.Header.Source)
			_, err = n.SendTo(pkt.Header.Source, statusTransportMessage)
			if err != nil {
				return false,
					xerrors.Errorf("[%s] failed to send status message back to %s : %v", n.GetAddress(), pkt.Header.Source, err)
			}

			return true, nil
		}

	}
	return false, nil
}

func (n *node) checkCase2(pkt transport.Packet, statusMessage *types.StatusMessage) (bool, error) {
	var missingRumors types.RumorBySeq
	for key, localValue := range n.view.Copy() {
		remoteValue, ok1 := statusMessage.View()[key]
		if !ok1 || localValue > remoteValue {
			// z.Logger.Debug().Msgf(
			// 	"[%s] case2:  This peer has Rumors that the remote peer (%s) doesn’t have (key:%s)",
			// 	n.GetAddress(), pkt.Header.Source, key,
			// )
			for _, rumor := range n.rumorsStore.Get(key) {
				if rumor.Sequence > remoteValue {
					missingRumors = append(missingRumors, rumor)
				}
			}
		}
	}
	// z.Logger.Debug().Msgf(
	// 	"[%s] %d rumors were missing in remote peer (%s) ",
	// 	n.GetAddress(), len(missingRumors), pkt.Header.Source,
	// )
	if len(missingRumors) > 0 {
		sort.Sort(missingRumors)
		rumorsTransportMessage, err := types.ToTransport(types.RumorsMessage{Rumors: missingRumors})
		if err != nil {
			return false,
				xerrors.Errorf("[%s] failed to build rumors transport message : %v", n.GetAddress(), err)
		}

		// z.Logger.Info().Msgf(
		// 	"[%s] send %d missing rumors back to %s",
		// 	n.GetAddress(), len(missingRumors), pkt.Header.Source,
		// )

		_, err = n.SendTo(pkt.Header.Source, rumorsTransportMessage)
		if err != nil {
			return false,
				xerrors.Errorf("[%s] failed to send missing rumors back to %s : %v", n.GetAddress(), pkt.Header.Source, err)
		}

		return true, nil
	}
	return false, nil
}

func (n *node) ExecEmptyMessage(msg types.Message, pkt transport.Packet) error {
	_, ok := msg.(*types.EmptyMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] empty message received from %s", n.GetAddress(), pkt.Header.Source)

	return nil
}

func (n *node) ExecPrivateMessage(msg types.Message, pkt transport.Packet) error {
	privateMessage, ok := msg.(*types.PrivateMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] private message received from %s", n.GetAddress(), pkt.Header.Source)

	_, authorized := privateMessage.Recipients[n.GetAddress()]
	if authorized {
		// Process pkt
		localPkt := transport.Packet{Header: pkt.Header, Msg: privateMessage.Msg}
		err := n.conf.MessageRegistry.ProcessPacket(localPkt)
		if err != nil {
			z.Logger.Err(err).Msgf("[%s] error while processing private message from %s", n.GetAddress(), pkt.Header.Source)
			return err
		}
	}

	return nil
}

func (n *node) ExecDataRequestMessage(msg types.Message, pkt transport.Packet) error {
	dataRequestMessage, ok := msg.(*types.DataRequestMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf(
	// 	"[%s] data request message received from %s for key %s",
	// 	n.GetAddress(),
	// 	pkt.Header.Source,
	// 	dataRequestMessage.Key,
	// )

	blobStore := n.conf.Storage.GetDataBlobStore()
	content := blobStore.Get(dataRequestMessage.Key)

	reply := types.DataReplyMessage{
		RequestID: dataRequestMessage.RequestID,
		Key:       dataRequestMessage.Key,
		Value:     content,
	}

	replyTransportMessage, err := types.ToTransport(reply)
	if err != nil {
		return xerrors.Errorf("failed to build reply transport message (requestID: %s)", dataRequestMessage.RequestID)
	}

	return n.Unicast(pkt.Header.Source, replyTransportMessage)
}

func (n *node) ExecDataReplyMessage(msg types.Message, pkt transport.Packet) error {
	dataReplyMessage, ok := msg.(*types.DataReplyMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] data reply message received from %s", n.GetAddress(), pkt.Header.Source)

	return n.requestManager.ReceiveDataReply(dataReplyMessage)
}

func (n *node) ExecSearchRequestMessage(msg types.Message, pkt transport.Packet) error {
	searchRequestMessage, ok := msg.(*types.SearchRequestMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf(
	// 	"[%s] search request message received from %s (budget:%d)",
	// 	n.GetAddress(),
	// 	pkt.Header.Source,
	// 	searchRequestMessage.Budget,
	// )

	// forwards the search if the budgets permits
	neighbors := n.GetNeighbors(pkt.Header.RelayedBy)
	if searchRequestMessage.Budget > 1 && len(neighbors) > 0 {
		budgets := DivideBudget(searchRequestMessage.Budget-1, neighbors)
		for i, neighbor := range neighbors {
			if budgets[i] == 0 {
				continue
			}

			forwardSearchRequestMessage := types.SearchRequestMessage{
				RequestID: searchRequestMessage.RequestID,
				Budget:    uint(budgets[i]),
				Pattern:   searchRequestMessage.Pattern,
				Origin:    searchRequestMessage.Origin,
			}

			transportMessage, err := types.ToTransport(forwardSearchRequestMessage)
			if err != nil {
				return xerrors.Errorf("failed to build a search request message: %v", err)
			}

			_, err = n.SendTo(neighbor, transportMessage)
			if err != nil {
				return xerrors.Errorf("failed to forward request message to %s: %v", neighbor, err)
			}
		}
	}

	//send back local matches
	matches := n.searchFilesLocally(searchRequestMessage.Pattern)
	var filesInfo []types.FileInfo

	for name, hash := range matches {
		fileInfo, hashChunk := n.constructFileInfo(name, hash)
		if !hashChunk {
			continue
		}

		filesInfo = append(filesInfo, fileInfo)
	}

	reply := types.SearchReplyMessage{
		RequestID: searchRequestMessage.RequestID,
		Responses: filesInfo,
	}

	replyTransportMessage, err := types.ToTransport(reply)
	if err != nil {
		return xerrors.Errorf("failed to build reply search transport message")
	}

	replyHeader := transport.NewHeader(n.GetAddress(), n.GetAddress(), searchRequestMessage.Origin, 0)
	replyPkt := transport.Packet{
		Header: &replyHeader,
		Msg:    &replyTransportMessage,
	}

	return n.conf.Socket.Send(pkt.Header.Source, replyPkt, 0)
}

func (n *node) ExecSearchReplyMessage(msg types.Message, pkt transport.Packet) error {
	searchReplyMessage, ok := msg.(*types.SearchReplyMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] search reply message received from %s", n.GetAddress(), pkt.Header.Source)

	for _, fileInfo := range searchReplyMessage.Responses {
		// update naming store
		_ = n.Tag(fileInfo.Name, fileInfo.Metahash)

		// update catalog
		n.UpdateCatalog(fileInfo.Metahash, pkt.Header.Source)
		for _, chunkHash := range fileInfo.Chunks {
			if len(chunkHash) > 0 {
				n.UpdateCatalog(string(chunkHash), pkt.Header.Source)
			}
		}
	}

	return n.requestManager.ReceiveSearchReply(searchReplyMessage)
}

func (n *node) ExecArticleSummaryMessage(msg types.Message, pkt transport.Packet) error {
	// z.Logger.Info().Msgf("[%s] ExecArticleSummaryMessage in", n.GetAddress())
	articleSummaryMessage, ok := msg.(*types.ArticleSummaryMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] article summary message received from %s", n.GetAddress(), pkt.Header.Source)

	if articleSummaryMessage.UserID != "" && !articleSummaryMessage.Verify(n.pkMap[articleSummaryMessage.UserID]) {
		// z.Logger.Info().Msgf("[%s] ExecArticleSummaryMessage out", n.GetAddress())
		return nil
	}

	n.summaryStore.Set(articleSummaryMessage.ArticleID, *articleSummaryMessage)

	timeout := time.Time{} // Zero value
	if n.conf.VoteTimeout != 0 {
		timeout = articleSummaryMessage.Timestamp.Add(n.conf.VoteTimeout)
	}
	n.voteStore.Register(articleSummaryMessage.ArticleID, articleSummaryMessage.Timestamp, timeout)

	// TODO: download this file with probability p

	// z.Logger.Info().Msgf("[%s] ExecArticleSummaryMessage out", n.GetAddress())
	return nil
}

func (n *node) ExecCommentMessage(msg types.Message, pkt transport.Packet) error {
	commentMessage, ok := msg.(*types.CommentMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] comment message received from %s", n.GetAddress(), pkt.Header.Source)

	n.commentStore.Add(*commentMessage)
	return nil
}

func (n *node) ExecVoteMessage(msg types.Message, pkt transport.Packet) error {
	voteMessage, ok := msg.(*types.VoteMessage)

	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// z.Logger.Info().Msgf("[%s] vote message received from %s", n.GetAddress(), pkt.Header.Source)

	pub, err := x509.ParsePKCS1PublicKey(voteMessage.PublicKey)
	if err != nil {
		return xerrors.Errorf("failed to parse vote public key: %v", err)
	}

	if !voteMessage.Verify(*pub) {
		return nil
	}

	// Don't count your own votes
	if pub.Equal(n.recommender.key.PublicKey) {
		return nil
	}

	// Check proof, if vote threshold reached
	articleID := voteMessage.ArticleID
	if uint(len(n.voteStore.Get(articleID))) >= n.conf.CheckProofThreshold {
		// z.Logger.Info().Msgf("[%s] vote message received: proof of work required", n.GetAddress())
		validProof := n.verifyProof(string(voteMessage.PublicKey), voteMessage.Timestamp, voteMessage.Proof)
		if !validProof {
			// z.Logger.Info().Msgf("[%s] vote message received: proof of work missing/invalid", n.GetAddress())
			// ignore vote since it doesn't have the required proof of work
			return nil
		}
	}

	n.voteStore.Add(*voteMessage)

	return nil
}
