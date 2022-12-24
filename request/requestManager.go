package request

import (
	"github.com/rs/xid"
	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"time"
)

func NewRequestManager(node peer.Peer, conf peer.Backoff) Manager {
	dataChannels := NewDataChannels()
	searchChannels := NewSearchChannels()
	return Manager{
		Conf:           conf,
		DataChannels:   dataChannels,
		SearchChannels: searchChannels,
		Node:           node,
	}
}

type Manager struct {
	Conf           peer.Backoff
	DataChannels   DataChannels
	SearchChannels SearchChannels
	Node           peer.Peer
}

func (rm *Manager) SendDataRequest(dest, key string) ([]byte, error) {
	requestID := xid.New().String()
	requestMessage := types.DataRequestMessage{
		RequestID: requestID,
		Key:       key,
	}

	rm.DataChannels.add(requestID, make(chan []byte))

	requestTransportMessage, err := types.ToTransport(requestMessage)
	if err != nil {
		return nil, xerrors.Errorf("unable to build a data request transport message: %v ", err)
	}

	err = rm.Node.Unicast(dest, requestTransportMessage)
	if err != nil {
		return nil, xerrors.Errorf("failed to unicast data request to %s: %v ", dest, err)
	}

	//blocks till gets a response back, uses backoff strategy after timeout
	timeout := rm.Conf.Initial
	for i := 0; i < int(rm.Conf.Retry); i++ {
		select {
		case response := <-rm.DataChannels.get(requestID):
			rm.DataChannels.del(requestID)
			if len(response) == 0 {
				return nil, xerrors.Errorf("receive empty value from %s", dest)
			}
			return response, nil
		case <-time.After(timeout):
			timeout *= time.Duration(int(rm.Conf.Retry))

			err = rm.Node.Unicast(dest, requestTransportMessage)
			if err != nil {
				return nil, xerrors.Errorf("failed to unicast data request to %s: %v ", dest, err)
			}
		}
	}
	return nil, xerrors.Errorf("backoff timeout: failed to get a response from %s", dest)
}

func (rm *Manager) SendSearchRequest(origin, pattern string, neighbors []string,
	budgets []int, timeout time.Duration) []types.FileInfo {

	requestID := xid.New().String()
	rm.SearchChannels.add(requestID, make(chan types.FileInfo))

	for i, neighbor := range neighbors {
		go func(dest string, budget int) {
			requestMessage := types.SearchRequestMessage{
				RequestID: requestID,
				Origin:    origin,
				Pattern:   pattern,
				Budget:    uint(budget),
			}

			requestTransportMessage, err := types.ToTransport(requestMessage)
			if err != nil {
				z.Logger.Err(err).Msg("unable to build a search request transport message")
				return
			}

			err = rm.Node.Unicast(dest, requestTransportMessage)
			if err != nil {
				z.Logger.Err(err).Msgf("failed to unicast search request to %s", dest)
				return
			}

		}(neighbor, budgets[i])
	}

	quit := make(chan int)
	go func() {
		time.Sleep(timeout)
		quit <- 0
	}()

	var responses []types.FileInfo
	for {
		select {
		case response := <-rm.SearchChannels.get(requestID):
			responses = append(responses, response)
		case <-quit:
			rm.SearchChannels.del(requestID)
			return responses
		}
	}
}

func (rm *Manager) ReceiveDataReply(reply *types.DataReplyMessage) error {
	channel := rm.DataChannels.get(reply.RequestID)
	if channel != nil {
		channel <- reply.Value
	}
	return nil
}

func (rm *Manager) ReceiveSearchReply(reply *types.SearchReplyMessage) error {
	channel := rm.SearchChannels.get(reply.RequestID)
	if channel != nil {
		for _, fileInfo := range reply.Responses {
			channel <- fileInfo
		}
	}
	return nil
}
