package impl

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/customCrypto"
	z "go.dedis.ch/cs438/logger"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

// GetDirectory implements peer.Tor
func (n *node) GetDirectory() map[string]*rsa.PublicKey {
	return n.conf.Directory.GetDir()
}

// CreateRandomCircuit implements peer.Tor
func (n *node) CreateRandomCircuit() (*types.ProxyCircuit, error) {

	z.Logger.Info().Msgf("[%s] Creating new random circuit", n.GetAddress())
	startTime := time.Now()

	torNodes, err := n.conf.Directory.GetRandomNodes(3, n.conf.Socket.GetAddress())
	if err != nil {
		return nil, xerrors.Errorf("error while generating random nodes for new circuit: %v", err)
	}

	circuit := types.ProxyCircuit{
		RelayCircuit: types.RelayCircuit{
			Id:           xid.New().String(),
			FirstNodeIp:  n.conf.Socket.GetAddress(),
			SecondNodeIp: torNodes[0],
			PrevCircuit:  nil,
			NextCircuit:  nil,
			SharedKey:    nil,
		},
		AllSharedKeys: nil,
	}
	n.proxyCircuits.Add(circuit.Id, &circuit)

	for i, nodeIp := range torNodes {

		myPrivateKey, myPublicKey := n.DHGenerateKeys()

		keyExchangeReqMsg := types.KeyExchangeRequestMessage{
			CircuitID: circuit.Id,
			PublicKey: myPublicKey,
		}

		if i > 0 {
			keyExchangeReqMsg.Extend = nodeIp
		}

		onionMsg, err := CreateFullOnion(keyExchangeReqMsg, circuit)
		if err != nil {
			return nil, xerrors.Errorf("error while putting key exchange request in onion: %v", err)
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onionMsg)
		if err != nil {
			return nil, xerrors.Errorf("error while marshaling onion message: %v", err)
		}

		_, err = n.SendTo(circuit.SecondNodeIp, transportMsg)
		if err != nil {
			return nil, xerrors.Errorf("error while sending onion message: %v", err)
		}

		n.keyExchangeReplyChannels.MakeChannel(circuit.Id)
		select {
		case keyExchangeReplyMsg := <-n.keyExchangeReplyChannels.Get(circuit.Id):
			hashed := sha256(keyExchangeReplyMsg.PublicKey.Bytes())

			if !customCrypto.VerifyRSA(n.conf.Directory.Get(nodeIp), hashed, keyExchangeReplyMsg.Signature) {
				n.proxyCircuits.Delete(keyExchangeReplyMsg.CircuitID)
				return nil, xerrors.Errorf("verification of key exchange reply message failed")
			}

			sharedKey, err := n.DHComputeSharedKey(myPrivateKey, keyExchangeReplyMsg.PublicKey)
			if err != nil {
				return nil, err
			}
			circuit.AllSharedKeys = append(circuit.AllSharedKeys, sharedKey.Bytes())
		case <-time.After(time.Second * 20):
			return nil, xerrors.Errorf("timed out while waiting for the key exchange reply message")
		}
	}

	n.proxyCircuits.Add(circuit.Id, &circuit)
	z.Logger.Info().Msgf("[%s] Created new random circuit with nodes: %s in %f seconds", n.GetAddress(), torNodes, time.Since(startTime).Seconds())

	return &circuit, nil
}

// This function encrypts the payload of an onion message with all the keys in the node's circuit, i.e. creates an onion.
func CreateFullOnion(msg types.Message, circuit types.ProxyCircuit) (*types.OnionMessage, error) {

	var err error
	marshaledMsg, err := json.Marshal(msg)
	if err != nil {
		return nil, xerrors.Errorf("error while marshaling message while creating Onion: %v", err)
	}

	onionMsg := types.OnionMessage{
		CircuitID: circuit.Id,
		Direction: true,
		Type:      msg.Name(),
		Payload:   marshaledMsg,
	}

	for i := range circuit.AllSharedKeys {
		key := circuit.AllSharedKeys[len(circuit.AllSharedKeys)-i-1]
		onionMsg.Payload, err = Encrypt(key, onionMsg.Payload)
		if err != nil {
			return nil, xerrors.Errorf("error while encrypting onion layer: %v", err)
		}
	}

	return &onionMsg, nil
}

// This function decrypts the payload of an onion message with all the keys in the node's circuit, i.e. peels an onion.
func PeelFullOnion(onionMsg types.OnionMessage, circuit types.ProxyCircuit) ([]byte, error) {

	var err error
	for _, key := range circuit.AllSharedKeys {
		onionMsg.Payload, err = Decrypt(key, onionMsg.Payload)
		if err != nil {
			return nil, xerrors.Errorf("error while decrypting onion message: %v", err)
		}
	}

	return onionMsg.Payload, nil
}

// Used only during the key exchange protocol.
func CreateRelayOnion(keyMsg types.KeyExchangeReplyMessage, circuit types.RelayCircuit) (*types.OnionMessage, error) {

	var err error
	marshaledMsg, err := json.Marshal(keyMsg)
	if err != nil {
		return nil, err
	}

	onionMsg := types.OnionMessage{
		CircuitID: circuit.Id,
		Direction: false,
		Type:      keyMsg.Name(),
		Payload:   marshaledMsg,
	}

	if circuit.SharedKey != nil {
		onionMsg.Payload, err = Encrypt(circuit.SharedKey, onionMsg.Payload)
		if err != nil {
			return nil, xerrors.Errorf("error while encrypting onion layer: %v", err)
		}
	}

	return &onionMsg, nil
}

/*
This function is used when sending a message via tor in order to encrypt
the message with all keys in the circuit.
*/
func FullEncryption(circuit types.ProxyCircuit, payload []byte) ([]byte, error) {

	var err error
	for i := range circuit.AllSharedKeys {
		sharedKey := circuit.AllSharedKeys[len(circuit.AllSharedKeys)-i-1]
		payload, err = Encrypt(sharedKey, payload)
		if err != nil {
			return nil, xerrors.Errorf("error while fully encrypting payload")
		}
	}

	return payload, nil
}

/*
This function is used when receiving a message via tor in order to decrypt
the message with all keys in the circuit.
*/
func FullDecryption(circuit types.ProxyCircuit, payload []byte) ([]byte, error) {

	var err error
	for _, sharedKey := range circuit.AllSharedKeys {
		payload, err = Decrypt(sharedKey, payload)
		if err != nil {
			return nil, xerrors.Errorf("error while fully decrypting payload")
		}
	}

	return payload, nil
}

/*
This function is used when a relay node gets some message that is being
forwarded in the backward direction through the circuit and needs to encrypt it.
*/
func RelayEncryption(circuit types.RelayCircuit, payload []byte) ([]byte, error) {

	var err error
	if circuit.SharedKey != nil {
		payload, err = Encrypt(circuit.SharedKey, payload)
		if err != nil {
			return nil, xerrors.Errorf("error while encrypting payload at relay node")
		}
	}

	return payload, nil
}

/*
This function is used when a relay node gets some message that is being
forwarded in the forward direction through the circuit and needs to decrypt it.
*/
func RelayDecryption(circuit types.RelayCircuit, payload []byte) ([]byte, error) {

	var err error
	if circuit.SharedKey != nil {
		payload, err = Decrypt(circuit.SharedKey, payload)
		if err != nil {
			return nil, xerrors.Errorf("error while decrypting payload at relay node")
		}
	}

	return payload, nil
}

// AnonymousPublishArticle implements peer.Tor
func (n *node) AnonymousPublishArticle(summary types.ArticleSummaryMessage, content string) error {

	circuit, err := n.CreateRandomCircuit()
	if err != nil {
		return err
	}

	article := types.AnonymousArticle{
		Summary: summary,
		Content: content,
	}

	payload, err := json.Marshal(article)
	if err != nil {
		return err
	}

	payload, err = FullEncryption(*circuit, payload)
	if err != nil {
		return err
	}

	anonymousArticleMsg := types.AnonymousArticleSummaryMessage{
		CircuitID: circuit.Id,
		Payload:   payload,
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousArticleMsg)
	if err != nil {
		return err
	}

	_, err = n.SendTo(circuit.SecondNodeIp, transportMsg)

	return err
}

// AnonymousDownloadArticle implements peer.Tor
func (n *node) AnonymousDownloadArticle(title, metahash string) ([]byte, error) {

	circuit, err := n.CreateRandomCircuit()
	if err != nil {
		return nil, err
	}

	articleInfo := types.ArticleInfo{
		Title:    title,
		Metahash: metahash,
	}

	payload, err := json.Marshal(articleInfo)
	if err != nil {
		return nil, err
	}

	payload, err = FullEncryption(*circuit, payload)
	if err != nil {
		return nil, err
	}

	anonymousDownloadReqMsg := types.AnonymousDownloadRequestMessage{
		CircuitID: circuit.Id,
		Payload:   payload,
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReqMsg)
	if err != nil {
		return nil, err
	}

	_, err = n.SendTo(circuit.SecondNodeIp, transportMsg)
	if err != nil {
		return nil, err
	}

	n.anonymousDownloadReplyChannels.MakeChannel(circuit.Id)
	select {
	case anonymousDownloadReplyMsg := <-n.anonymousDownloadReplyChannels.Get(circuit.Id):
		payload, err := FullDecryption(*circuit, anonymousDownloadReplyMsg.Payload)
		if err != nil {
			return nil, err
		}

		// Upload the downloaded file into the node's storage.
		metahash, err = n.Upload(bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		n.Tag(title, metahash)

		return payload, nil

	case <-time.After(time.Second * 10):
		return nil, xerrors.Errorf("timed out while waiting for anonymous download reply")
	}
}

func (n *node) ExecOnionMessage(msg types.Message, packet transport.Packet) error {

	onionMsg, ok := msg.(*types.OnionMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}
	z.Logger.Info().Msgf("[%s] handling Onion message from %s", n.GetAddress(), packet.Header.Source)
	var err error
	proxyCircuit := n.proxyCircuits.Get(onionMsg.CircuitID)
	relayCircuit := n.relayCircuits.Get(onionMsg.CircuitID)

	if proxyCircuit != nil {

		z.Logger.Info().Msgf("[%s] I am the proxy for the Onion message", n.GetAddress())
		onionMsg.Payload, err = PeelFullOnion(*onionMsg, *proxyCircuit)
		if err != nil {
			return xerrors.Errorf("error while peeling whole onion: %v", err)
		}

		if onionMsg.Type == (types.KeyExchangeReplyMessage{}).Name() {
			var keyExchangeReplyMsg types.KeyExchangeReplyMessage
			err = json.Unmarshal(onionMsg.Payload, &keyExchangeReplyMsg)
			if err != nil {
				return xerrors.Errorf("error while unmarshaling onion payload")
			}
			keyExchangeReplyMsg.CircuitID = onionMsg.CircuitID
			onionMsg.Payload, err = json.Marshal(keyExchangeReplyMsg)
			if err != nil {
				return xerrors.Errorf("error while marshaling key exchange reply message")
			}
		}

		newPacket := transport.Packet{
			Header: packet.Header,
			Msg: &transport.Message{
				Type:    onionMsg.Type,
				Payload: onionMsg.Payload,
			},
		}

		return n.conf.MessageRegistry.ProcessPacket(newPacket)

	} else if relayCircuit != nil {

		z.Logger.Info().Msgf("[%s] I am the relay for the Onion message", n.GetAddress())
		var nextHop string
		if onionMsg.Direction { // If direction is forward.
			onionMsg.Payload, err = Decrypt(relayCircuit.SharedKey, onionMsg.Payload)
			if err != nil {
				return xerrors.Errorf("error while decrypting onion message: %v", err)
			}

			if relayCircuit.NextCircuit == nil {
				var keyExchangeReqMsg types.KeyExchangeRequestMessage
				err = json.Unmarshal(onionMsg.Payload, &keyExchangeReqMsg)
				if err != nil {
					return xerrors.Errorf("error while unmarshaling onion message in order to extend circuit: %v", err)
				}

				newCircuit := types.RelayCircuit{
					Id:           xid.New().String(),
					FirstNodeIp:  relayCircuit.SecondNodeIp,
					SecondNodeIp: keyExchangeReqMsg.Extend,
					PrevCircuit:  relayCircuit,
					NextCircuit:  nil,
					SharedKey:    nil,
				}

				relayCircuit.NextCircuit = &newCircuit
				n.relayCircuits.Add(newCircuit.Id, &newCircuit)

				keyExchangeReqMsg.CircuitID = newCircuit.Id
				onionMsg.Payload, err = json.Marshal(keyExchangeReqMsg)
				if err != nil {
					return xerrors.Errorf("error while marshaling key exchange request message in order to extend circuit: %v", err)
				}
			}

			onionMsg.CircuitID = relayCircuit.NextCircuit.Id
			nextHop = relayCircuit.NextCircuit.SecondNodeIp
		} else { // If direction is backward.
			prevCircuit := relayCircuit.PrevCircuit
			if prevCircuit == nil {
				return xerrors.Errorf("no previous circuit to use to send onion backwards: %v", err)
			}
			onionMsg.Payload, err = Encrypt(prevCircuit.SharedKey, onionMsg.Payload)
			if err != nil {
				return xerrors.Errorf("error while encrypting onion payload: %v", err)
			}
			onionMsg.CircuitID = prevCircuit.Id
			nextHop = prevCircuit.FirstNodeIp
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onionMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling onion message: %v", err)
		}
		_, err = n.SendTo(nextHop, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending onion: %v", err)
		}

	} else {
		z.Logger.Info().Msgf("[%s] Received Key Exchange Request Message from the onion", n.GetAddress())
		if onionMsg.Type == types.KeyExchangeRequestMessage.Name(types.KeyExchangeRequestMessage{}) {
			newPacket := transport.Packet{
				Header: packet.Header,
				Msg: &transport.Message{
					Type:    onionMsg.Type,
					Payload: onionMsg.Payload,
				},
			}
			return n.conf.MessageRegistry.ProcessPacket(newPacket)
		}

		return xerrors.Errorf("circuit ID of onion message is unknown: %v", err)
	}

	return nil
}

func (n *node) ExecKeyExchangeRequestMessage(msg types.Message, packet transport.Packet) error {

	keyExchangeReqMsg, ok := msg.(*types.KeyExchangeRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	z.Logger.Info().Msgf("[%s] handling Key Exchange Request message", n.GetAddress())

	var err error
	relayCircuit := n.relayCircuits.Get(keyExchangeReqMsg.CircuitID)

	if relayCircuit == nil {

		newCircuit := types.RelayCircuit{
			Id:           keyExchangeReqMsg.CircuitID,
			FirstNodeIp:  packet.Header.Source,
			SecondNodeIp: n.conf.Socket.GetAddress(),
			PrevCircuit:  nil,
			NextCircuit:  nil,
			SharedKey:    nil,
		}

		myPrivateKey, myPublicKey := n.DHGenerateKeys()

		keyExchangeReplyMsg := types.KeyExchangeReplyMessage{
			CircuitID: keyExchangeReqMsg.CircuitID,
			PublicKey: myPublicKey,
		}
		hashed := sha256(keyExchangeReplyMsg.PublicKey.Bytes())

		keyExchangeReplyMsg.Signature, err = customCrypto.SignRSA(n.conf.PrivateKey, hashed)
		if err != nil {
			return err
		}

		sharedKey, err := n.DHComputeSharedKey(myPrivateKey, keyExchangeReqMsg.PublicKey)
		if err != nil {
			return err
		}

		onionMsg, err := CreateRelayOnion(keyExchangeReplyMsg, newCircuit)
		if err != nil {
			return err
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onionMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling key exchange reply message")
		}

		_, err = n.SendTo(newCircuit.FirstNodeIp, transportMsg)
		if err != nil {
			return err
		}

		newCircuit.SharedKey = sharedKey.Bytes()
		n.relayCircuits.Add(newCircuit.Id, &newCircuit)

	} else if relayCircuit.NextCircuit == nil && keyExchangeReqMsg.Extend != n.conf.Socket.GetAddress() {
		newCircuit := types.RelayCircuit{
			Id:           xid.New().String(),
			FirstNodeIp:  relayCircuit.SecondNodeIp,
			SecondNodeIp: keyExchangeReqMsg.Extend,
			PrevCircuit:  relayCircuit,
			NextCircuit:  nil,
			SharedKey:    nil,
		}

		relayCircuit.NextCircuit = &newCircuit
		n.relayCircuits.Add(newCircuit.Id, &newCircuit)

		keyExchangeReqMsg.CircuitID = newCircuit.Id
		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(keyExchangeReqMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling key exchange request message while forwarding it: %v", err)
		}

		_, err = n.SendTo(keyExchangeReqMsg.Extend, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while forwarding key exchange request message: %v", err)
		}
	} else if relayCircuit.NextCircuit != nil && keyExchangeReqMsg.Extend != n.conf.Socket.GetAddress() {
		keyExchangeReqMsg.CircuitID = relayCircuit.NextCircuit.Id
		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(keyExchangeReqMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling key exchange request message while forwarding it: %v", err)
		}

		_, err = n.SendTo(keyExchangeReqMsg.Extend, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while forwarding key exchange request message: %v", err)
		}
	} else {
		return xerrors.Errorf("failed to extend circuit")
	}

	return nil
}

func (n *node) ExecKeyExchangeReplyMessage(msg types.Message, packet transport.Packet) error {

	keyExchangeReplyMsg, ok := msg.(*types.KeyExchangeReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	z.Logger.Info().Msgf("[%s] handling Key Exchange Reply message", n.GetAddress())

	proxyCircuit := n.proxyCircuits.Get(keyExchangeReplyMsg.CircuitID)

	if proxyCircuit != nil {
		z.Logger.Info().Msgf("[%s] The Key Exchange Reply message is for me", n.GetAddress())
		n.keyExchangeReplyChannels.Get(keyExchangeReplyMsg.CircuitID) <- *keyExchangeReplyMsg
	} else {
		return xerrors.Errorf("circuit ID of key exchange reply message unknwon")
	}

	return nil
}

func (n *node) ExecAnonymousArticleSummaryMessage(msg types.Message, packet transport.Packet) error {

	anonymousArticleMsg, ok := msg.(*types.AnonymousArticleSummaryMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	z.Logger.Info().Msgf("[%s] handling Anonymous Article Summary message", n.GetAddress())

	relayCircuit := n.relayCircuits.Get(anonymousArticleMsg.CircuitID)
	if relayCircuit == nil {
		return xerrors.Errorf("no relay circuit found for anonymous article message")
	}

	payload, err := RelayDecryption(*relayCircuit, anonymousArticleMsg.Payload)
	if err != nil {
		return xerrors.Errorf("error while decrypting anonymous article message: %v", err)
	}

	if relayCircuit.NextCircuit != nil { // Case in which this node is a relay node.

		anonymousArticleMsg.CircuitID = relayCircuit.NextCircuit.Id
		anonymousArticleMsg.Payload = payload

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousArticleMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling anonymous article message: %v", err)
		}

		_, err = n.SendTo(relayCircuit.NextCircuit.SecondNodeIp, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending anonymous article message: %v", err)
		}
	} else { // Case in which this node is an exit node.

		var article types.AnonymousArticle
		err = json.Unmarshal(payload, &article)
		if err != nil {
			return err
		}

		metahash, err := n.Upload(bytes.NewBuffer([]byte(article.Content)))
		if err != nil {
			return err
		}
		n.Tag(article.Summary.Title, metahash)

		summary, err := json.Marshal(article.Summary)
		if err != nil {
			return err
		}

		transportMsg := transport.Message{
			Type:    types.ArticleSummaryMessage{}.Name(),
			Payload: summary,
		}

		n.Broadcast(transportMsg)
	}

	return nil
}

func (n *node) ExecAnonymousDownloadRequestMessage(msg types.Message, packet transport.Packet) error {

	anonymousDownloadReqMsg, ok := msg.(*types.AnonymousDownloadRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	z.Logger.Info().Msgf("[%s] handling Anonymous Download Request message", n.GetAddress())

	relayCircuit := n.relayCircuits.Get(anonymousDownloadReqMsg.CircuitID)
	if relayCircuit == nil {
		return xerrors.Errorf("no relay circuit found for anonymous download message")
	}

	payload, err := RelayDecryption(*relayCircuit, anonymousDownloadReqMsg.Payload)
	if err != nil {
		return xerrors.Errorf("error while decrypting anonymous article message: %v", err)
	}

	if relayCircuit.NextCircuit != nil { // Case in which this node is a relay node.

		anonymousDownloadReqMsg.CircuitID = relayCircuit.NextCircuit.Id
		anonymousDownloadReqMsg.Payload = payload

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReqMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling anonymous download message: %v", err)
		}

		_, err = n.SendTo(relayCircuit.NextCircuit.SecondNodeIp, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending anonymous download message: %v", err)
		}
	} else { // Case in which this node is an exit node.

		var articleInfo types.ArticleInfo
		err := json.Unmarshal(payload, &articleInfo)
		if err != nil {
			return xerrors.Errorf("error while unmarshaling article info from anonymous download message: %v", err)
		}

		n.DownloadThread(articleInfo, *anonymousDownloadReqMsg, *relayCircuit)

	}

	return nil
}

func (n *node) DownloadThread(articleInfo types.ArticleInfo, msg types.AnonymousDownloadRequestMessage, relayCircuit types.RelayCircuit) {
	go func() {
		file, err := n.DownloadArticle(articleInfo.Title, articleInfo.Metahash)
		if err != nil {
			return
		}

		replyPayload, err := RelayEncryption(relayCircuit, file)
		if err != nil {
			return
		}

		anonymousDownloadReplyMsg := types.AnonymousDownloadReplyMessage{
			CircuitID: msg.CircuitID,
			Payload:   replyPayload,
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReplyMsg)
		if err != nil {
			return
		}

		_, err = n.SendTo(relayCircuit.FirstNodeIp, transportMsg)
		if err != nil {
			return
		}
	}()
}

func (n *node) ExecAnonymousDownloadReplyMessage(msg types.Message, packet transport.Packet) error {

	anonymousDownloadReplyMsg, ok := msg.(*types.AnonymousDownloadReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	z.Logger.Info().Msgf("[%s] handling Anonymous Download Reply message", n.GetAddress())

	proxyCircuit := n.proxyCircuits.Get(anonymousDownloadReplyMsg.CircuitID)
	relayCircuit := n.relayCircuits.Get(anonymousDownloadReplyMsg.CircuitID)

	if proxyCircuit == nil && relayCircuit == nil {
		return xerrors.Errorf("cannot find circuit for anonymous download reply message which was received")
	}

	if proxyCircuit != nil { // Case in which this node is the originator of the anonymous download.
		go func() {
			n.anonymousDownloadReplyChannels.Add(anonymousDownloadReplyMsg.CircuitID, *anonymousDownloadReplyMsg)
		}()
	} else if relayCircuit != nil { // Case in which this node is just a relay.

		payload, err := RelayEncryption(*relayCircuit.PrevCircuit, anonymousDownloadReplyMsg.Payload)
		if err != nil {
			return err
		}

		anonymousDownloadReplyMsg.CircuitID = relayCircuit.PrevCircuit.Id
		anonymousDownloadReplyMsg.Payload = payload

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReplyMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling anonymous download reply message: %v", err)
		}

		_, err = n.SendTo(relayCircuit.PrevCircuit.FirstNodeIp, transportMsg)
		if err != nil {
			return err
		}
	}

	return nil
}
