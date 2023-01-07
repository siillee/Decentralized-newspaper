package impl

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

/*
This function gets public keys from the "directory nodes".
In our implementation those are just 5 nodes started at the beginning.
Their addresses are hard-coded in every node.
*/
func (n *node) GetDirectoryServerKeys() {

	directoryNodes := []string{"127.0.0.1:2000", "127.0.0.1:2001", "127.0.0.1:2002", "127.0.0.1:2003", "127.0.0.1:2004"}

	go func() {
		for _, ip := range directoryNodes {

			n.AddPeer(ip)

			// No need to send the request message to yourself.
			if ip == n.conf.Socket.GetAddress() {
				continue
			}

			torNodeInfoRequestMsg := types.TorNodeInfoRequestMessage{Ip: n.conf.Socket.GetAddress()}
			transportMsg, err := n.conf.MessageRegistry.MarshalMessage(torNodeInfoRequestMsg)
			if err != nil {
				// n.log.Err(xerrors.Errorf("error while marshaling tor node info request message: %v", err))
				continue
			}

			// Loop until you see the node in the directory. The loop is needed because there could be
			// messages lost when starting up the first "directory nodes".
			for !n.directory.Contains(ip) {
				fmt.Printf("%s : Sending info request to %s \n", n.conf.Socket.GetAddress(), ip)
				_, err = n.SendTo(ip, transportMsg)
				if err != nil {
					// n.log.Err(xerrors.Errorf("error while sending tor node info request message: %v", err))
					continue
				}
				time.Sleep(time.Millisecond * 50)
			}
		}
	}()
}

// GetDirectory implements peer.Tor
func (n *node) GetDirectory() map[string]types.TorNode {
	return n.directory.GetDir()
}

// CreateRandomCircuit implements peer.Tor
func (n *node) CreateRandomCircuit() (*types.ProxyCircuit, error) {

	torNodes, err := n.directory.GetRandomNodes(3, n.conf.Socket.GetAddress())
	if err != nil {
		return nil, xerrors.Errorf("error while generating random nodes for new circuit: %v", err)
	}

	circuit := types.ProxyCircuit{
		RelayCircuit: types.RelayCircuit{
			Id:          xid.New().String(),
			FirstNode:   n.directory.Get(n.conf.Socket.GetAddress()),
			SecondNode:  n.directory.Get(torNodes[0]),
			PrevCircuit: nil,
			NextCircuit: nil,
			SharedKey:   nil,
		},
		AllSharedKeys: nil,
	}

	for i, node := range torNodes {
		// TODO: Generate parameters using Diffie-Hellman

		keyExchangeReqMsg := types.KeyExchangeRequestMessage{
			CircuitID:  circuit.Id,
			Parameters: nil, // TODO: Add public key from Diffie-Hellman
		}

		if i > 0 {
			keyExchangeReqMsg.Extend = node
		}

		onionMsg, err := CreateFullOnion(keyExchangeReqMsg, circuit)
		if err != nil {
			return nil, xerrors.Errorf("error while putting key exchange request in onion: %v", err)
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onionMsg)
		if err != nil {
			return nil, xerrors.Errorf("error while marshaling onion message: %v", err)
		}

		_, err = n.SendTo(circuit.SecondNode.Ip, transportMsg)
		if err != nil {
			return nil, xerrors.Errorf("error while sending onion message via direct unicast: %v", err)
		}

		// TODO: Wait for key exchange response and do something based on that.
		// select {
		// case keyExchangeReplyMsg := <-n.keyExchangeReplyChannels.Get(circuit.Id):
		// 	// TODO: verify response and add shared key to circuit
		// }
	}

	n.proxyCircuits.Add(circuit.Id, &circuit)

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

func CreateRelayOnion(onionMsg types.OnionMessage, circuit types.RelayCircuit) ([]byte, error) {

	var err error
	if circuit.SharedKey != nil {
		onionMsg.Payload, err = Encrypt(circuit.SharedKey, onionMsg.Payload)
		if err != nil {
			return nil, xerrors.Errorf("error while encrypting onion layer: %v", err)
		}
	}

	return onionMsg.Payload, nil
}

func PeelRelayOnion(onionMsg types.OnionMessage, circuit types.RelayCircuit) ([]byte, error) {

	var err error
	if circuit.SharedKey != nil {
		onionMsg.Payload, err = Decrypt(circuit.SharedKey, onionMsg.Payload)
		if err != nil {
			return nil, xerrors.Errorf("error while decrypting onion message: %v", err)
		}
	}

	return onionMsg.Payload, nil
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

// SendAnonymousArticleSummaryMessage implements peer.Tor
func (n *node) SendAnonymousArticleSummaryMessage(article types.ArticleSummaryMessage) error {

	// TODO: see if this function will have Article as parameter or create the article here.

	circuit, err := n.CreateRandomCircuit()
	if err != nil {
		return err
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

	_, err = n.SendTo(circuit.SecondNode.Ip, transportMsg)

	return err
}

// SendAnonymousDownloadRequestMessage implements peer.Tor
func (n *node) SendAnonymousDownloadRequestMessage(title, metahash string) error {

	// TODO: see what the parameters are gonna be for this function.

	circuit, err := n.CreateRandomCircuit()
	if err != nil {
		return err
	}

	articleInfo := types.ArticleInfo{
		Title:    title,
		Metahash: metahash,
	}

	payload, err := json.Marshal(articleInfo)
	if err != nil {
		return nil
	}

	payload, err = FullEncryption(*circuit, payload)
	if err != nil {
		return err
	}

	anonymousDownloadReqMsg := types.AnonymousDownloadRequestMessage{
		CircuitID: circuit.Id,
		Payload:   payload,
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReqMsg)
	if err != nil {
		return err
	}

	_, err = n.SendTo(circuit.SecondNode.Ip, transportMsg)

	return err
}

func (n *node) ExecOnionMessage(msg types.Message, packet transport.Packet) error {

	onionMsg, ok := msg.(*types.OnionMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	var err error
	proxyCircuit := n.proxyCircuits.Get(onionMsg.CircuitID)
	relayCircuit := n.relayCircuits.Get(onionMsg.CircuitID)

	if proxyCircuit != nil {

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
					Id:          xid.New().String(),
					FirstNode:   relayCircuit.SecondNode,
					SecondNode:  n.directory.Get(keyExchangeReqMsg.Extend),
					PrevCircuit: relayCircuit,
					NextCircuit: nil,
					SharedKey:   nil,
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
			nextHop = relayCircuit.NextCircuit.SecondNode.Ip
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
			nextHop = prevCircuit.FirstNode.Ip
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onionMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling onion message: %v", err)
		}
		_, err = n.SendTo(nextHop, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending onion via unicast: %v", err)
		}

	} else {
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

// Possibly a good idea: KeyExchangeRequestMessage contains CircuitID and DHPublicKeyMessage, and when you execute
// it, you execute the DHPublicKeyMessage, and in the ExecDHPublicKeyMessage, the reply is put into
// KeyExchangeReplyMessage, with the same fields as KeyExchangeRequestMessage (just CircuitID and DHPublicKeyMessage)

// But how to get the needed CircuitID????? (for the idea above) --- Maybe just put it in the DHPublicKeyMessage
func (n *node) ExecKeyExchangeRequestMessage(msg types.Message, packet transport.Packet) error {

	keyExchangeReqMsg, ok := msg.(*types.KeyExchangeRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	relayCircuit := n.relayCircuits.Get(keyExchangeReqMsg.CircuitID)

	if relayCircuit == nil {

		newCircuit := types.RelayCircuit{
			Id:          keyExchangeReqMsg.CircuitID,
			FirstNode:   n.directory.Get(packet.Header.Source),
			SecondNode:  n.directory.Get(n.conf.Socket.GetAddress()),
			PrevCircuit: nil,
			NextCircuit: nil,
			SharedKey:   nil,
		}

		keyExchangeReplyMsg := types.KeyExchangeReplyMessage{
			CircuitID:  keyExchangeReqMsg.CircuitID,
			Parameters: nil, // TODO: Add public key from Diffie Hellman
		}

		keyExchangeReplyMsg.Signature = nil //TODO: Sign using rsa
		// TODO: sending of reply and putting shared key in the newCircuit

		n.relayCircuits.Add(newCircuit.Id, &newCircuit)
	} else if relayCircuit.NextCircuit == nil && keyExchangeReqMsg.Extend != n.conf.Socket.GetAddress() {
		newCircuit := types.RelayCircuit{
			Id:          xid.New().String(),
			FirstNode:   relayCircuit.SecondNode,
			SecondNode:  n.directory.Get(keyExchangeReqMsg.Extend),
			PrevCircuit: relayCircuit,
			NextCircuit: nil,
			SharedKey:   nil,
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
			return xerrors.Errorf("error while forwarding key exchange request message via Unicast: %v", err)
		}
	} else if relayCircuit.NextCircuit != nil && keyExchangeReqMsg.Extend != n.conf.Socket.GetAddress() {
		keyExchangeReqMsg.CircuitID = relayCircuit.NextCircuit.Id
		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(keyExchangeReqMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling key exchange request message while forwarding it: %v", err)
		}

		_, err = n.SendTo(keyExchangeReqMsg.Extend, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while forwarding key exchange request message via Unicast: %v", err)
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

	proxyCircuit := n.proxyCircuits.Get(keyExchangeReplyMsg.CircuitID)
	relayCircuit := n.relayCircuits.Get(keyExchangeReplyMsg.CircuitID)

	if proxyCircuit != nil {
		n.keyExchangeReplyChannels.Get(keyExchangeReplyMsg.CircuitID) <- *keyExchangeReplyMsg
	} else if relayCircuit != nil {
		prevCircuit := relayCircuit.PrevCircuit
		if prevCircuit == nil {
			return xerrors.Errorf("no previous circuit to forward the key exchange reply message to")
		}
		keyExchangeReplyMsg.CircuitID = prevCircuit.Id

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(keyExchangeReplyMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling key exchange reply message when forwarding it: %v", err)
		}

		_, err = n.SendTo(relayCircuit.FirstNode.Ip, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending key exchange reply message via Unicast: %v", err)
		}
	} else {
		return xerrors.Errorf("circuit ID of key exchange reply message unknwon")
	}

	return nil
}

func (n *node) ExecTorNodeInfoRequestMessage(msg types.Message, packet transport.Packet) error {

	_, ok := msg.(*types.TorNodeInfoRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	torNodeInfoReplyMsg := types.TorNodeInfoReplyMessage{
		Ip: n.conf.Socket.GetAddress(),
		Pk: &n.conf.PrivateKey.PublicKey,
	}
	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(torNodeInfoReplyMsg)
	if err != nil {
		// n.log.Err(xerrors.Errorf("error while marshaling tor node info reply message: %v", err))
		return err
	}
	_, err = n.SendTo(packet.Header.Source, transportMsg)

	return err
}

func (n *node) ExecTorNodeInfoReplyMessage(msg types.Message, packet transport.Packet) error {

	torNodeInfoReplyMsg, ok := msg.(*types.TorNodeInfoReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	check := n.directory.Add(torNodeInfoReplyMsg.Ip, types.TorNode{Ip: torNodeInfoReplyMsg.Ip, Pk: torNodeInfoReplyMsg.Pk})
	if !check {
		return xerrors.Errorf("node already in directory")
	}

	return nil
}

func (n *node) ExecAnonymousArticleSummaryMessage(msg types.Message, packet transport.Packet) error {

	anonymousArticleMsg, ok := msg.(*types.AnonymousArticleSummaryMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

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

		_, err = n.SendTo(relayCircuit.NextCircuit.SecondNode.Ip, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending anonymous article message via unicast: %v", err)
		}
	} else { // Case in which this node is an exit node.

		transportMsg := transport.Message{
			Type:    types.ArticleSummaryMessage{}.Name(),
			Payload: payload,
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

		_, err = n.SendTo(relayCircuit.NextCircuit.SecondNode.Ip, transportMsg)
		if err != nil {
			return xerrors.Errorf("error while sending anonymous download message via unicast: %v", err)
		}
	} else { // Case in which this node is an exit node.

		var articleInfo types.ArticleInfo
		err := json.Unmarshal(payload, &articleInfo)
		if err != nil {
			return xerrors.Errorf("error while unmarshaling article info from anonymous download message: %v", err)
		}

		// regexp := *regexp.MustCompile(articleInfo.Title)
		// responses, err := n.SearchAll(regexp, 10, time.Millisecond*200)
		// if err != nil {
		// 	return xerrors.Errorf("error while searching for file name to download")
		// }

		// DownloadArticle function is from user.go
		file, err := n.DownloadArticle(articleInfo.Title, articleInfo.Metahash)
		if err != nil {
			return err
		}

		// TODO: Send reply through the circuit
		replyPayload, err := RelayEncryption(*relayCircuit, file)
		if err != nil {
			return err
		}

		anonymousDownloadReplyMsg := types.AnonymousDownloadReplyMessage{
			CircuitID: anonymousDownloadReqMsg.CircuitID,
			Payload:   replyPayload,
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(anonymousDownloadReplyMsg)
		if err != nil {
			return xerrors.Errorf("error while marshaling anonymous data reply message")
		}

		_, err = n.SendTo(relayCircuit.FirstNode.Ip, transportMsg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (n *node) ExecAnonymousDownloadReplyMessage(msg types.Message, packet transport.Packet) error {

	anonymousDownloadReplyMsg, ok := msg.(*types.AnonymousDownloadReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong message type: %T", msg)
	}

	proxyCircuit := n.proxyCircuits.Get(anonymousDownloadReplyMsg.CircuitID)
	relayCircuit := n.relayCircuits.Get(anonymousDownloadReplyMsg.CircuitID)

	if proxyCircuit == nil && relayCircuit == nil {
		return xerrors.Errorf("cannot find circuit for anonymous download reply message which was received")
	}

	if proxyCircuit != nil { // Case in which this node is the originator of the anonymous download.

		// payload, err := FullDecryption(*proxyCircuit, anonymousDownloadReplyMsg.Payload)
		// if err != nil {
		// 	return err
		// }

		// TODO: what to do with payload? add to blobStore, or notify some other function, etc...?

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

		_, err = n.SendTo(relayCircuit.PrevCircuit.FirstNode.Ip, transportMsg)
		if err != nil {
			return err
		}
	}

	return nil
}
