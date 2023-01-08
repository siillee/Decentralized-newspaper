package types

import (
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"sync"

	"golang.org/x/xerrors"
)

// Information about a node in the network.
type TorNode struct {
	Ip string
	Pk *ecdsa.PublicKey
}

/*
A map which contains information about nodes participating in the Tor network.
It is thread-safe and has some basic functionalities.
*/
type Directory struct {
	sync.Mutex
	Dir map[string]TorNode
}

func (d *Directory) Add(ip string, info TorNode) bool {
	d.Lock()
	defer d.Unlock()

	_, check := d.Dir[ip]
	if check {
		return false
	}

	d.Dir[ip] = info
	return true
}

func (d *Directory) Get(ip string) TorNode {
	d.Lock()
	defer d.Unlock()

	return d.Dir[ip]
}

func (d *Directory) GetDir() map[string]TorNode {
	d.Lock()
	defer d.Unlock()

	return d.Dir
}

func (d *Directory) Contains(ip string) bool {
	d.Lock()
	defer d.Unlock()

	_, check := d.Dir[ip]

	return check
}

func (d *Directory) GetRandomNodes(num int, excluded ...string) ([]string, error) {
	d.Lock()
	defer d.Unlock()

	if len(d.Dir)-len(excluded) < num {
		return nil, xerrors.Errorf("not enough nodes in the directory to pick %d random ones ", num)
	}

	possibleNodes := make([]string, 0)
	for _, torNode := range d.Dir {
		if !contains(excluded, torNode.Ip) {
			possibleNodes = append(possibleNodes, torNode.Ip)
		}
	}

	result := make([]string, 0)
	randomIndexes := rand.Perm(len(possibleNodes))[:num]
	for _, index := range randomIndexes {
		result = append(result, possibleNodes[index])
	}

	return result, nil
}

func contains(arr []string, str string) bool {

	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}

type RelayCircuit struct {
	Id          string
	FirstNode   TorNode
	SecondNode  TorNode
	PrevCircuit *RelayCircuit
	NextCircuit *RelayCircuit
	SharedKey   []byte // Key generated in the key exchange protocol.
}

type ProxyCircuit struct {
	RelayCircuit
	AllSharedKeys [][]byte // Keys generated with all nodes in the circuit, used for creating an onion.
}

/*
A thread-safe map containing all relay circuits this node is a part of.
Has some basic functionalities.
*/
type ConcurrentRelayCircuits struct {
	sync.Mutex
	RelayCircuits map[string]*RelayCircuit
}

func (crc *ConcurrentRelayCircuits) Add(id string, circuit *RelayCircuit) {
	crc.Lock()
	defer crc.Unlock()

	crc.RelayCircuits[id] = circuit
}

func (crc *ConcurrentRelayCircuits) Get(id string) *RelayCircuit {
	crc.Lock()
	defer crc.Unlock()

	return crc.RelayCircuits[id]
}

/*
A thread-safe map containing all proxy circuits this node is a part of.
Has some basic functionalities.
*/
type ConcurrentProxyCircuits struct {
	sync.Mutex
	ProxyCircuits map[string]*ProxyCircuit
}

func (cpc *ConcurrentProxyCircuits) Add(id string, circuit *ProxyCircuit) {
	cpc.Lock()
	defer cpc.Unlock()

	cpc.ProxyCircuits[id] = circuit
}

func (cpc *ConcurrentProxyCircuits) Get(id string) *ProxyCircuit {
	cpc.Lock()
	defer cpc.Unlock()

	// circuit, check := cpc.ProxyCircuits[id]
	// if check {
	// 	return circuit
	// }

	// return nil
	return cpc.ProxyCircuits[id]
}

/*
A thread-safe map containing channels for key exchange reply messages.
Has some basic functionalities.
*/
type KeyExchangeReplyChannels struct {
	sync.Mutex
	ChannelMap map[string](chan KeyExchangeReplyMessage)
}

func (kepc *KeyExchangeReplyChannels) Add(id string, msg KeyExchangeReplyMessage) {
	kepc.Lock()
	defer kepc.Unlock()

	_, check := kepc.ChannelMap[id]
	if !check {
		kepc.ChannelMap[id] = make(chan KeyExchangeReplyMessage)
	}
	kepc.ChannelMap[id] <- msg
}

func (kepc *KeyExchangeReplyChannels) Get(id string) chan KeyExchangeReplyMessage {
	kepc.Lock()
	defer kepc.Unlock()

	return kepc.ChannelMap[id]
}

//------------------------------Messages------------------------------

// Structs representing messages necessary for the Diffie-Hellman key exchange protocol.
type KeyExchangeRequestMessage struct {
	CircuitID string
	PublicKey *big.Int
	Extend    string
}

type KeyExchangeReplyMessage struct {
	CircuitID string
	PublicKey *big.Int
	Signature []byte
}

type OnionMessage struct {
	CircuitID string
	Direction bool // Direction of the flow of the onion messages. True if forward, false if backwards.
	Type      string
	Payload   []byte
}

type AnonymousArticleSummaryMessage struct {
	CircuitID string
	// ArticleSummaryMessage --- in form of byte array payload
	Payload []byte
}

type AnonymousDownloadRequestMessage struct {
	CircuitID string
	// Information on wanted article (type ArticleInfo) --- in form of byte array payload
	Payload []byte
}

type AnonymousDownloadReplyMessage struct {
	CircuitID string
	// Information on wanted article (type ArticleInfo) --- in form of byte array payload
	Payload []byte
}

// Structs representing messages necessary for getting info on tor nodes from directory nodes.
type TorNodeInfoRequestMessage struct {
	Ip string
}

type TorNodeInfoReplyMessage struct {
	Ip string
	Pk *ecdsa.PublicKey
}

//------------------------------Helper structs------------------------------

type ArticleInfo struct {
	Title    string
	Metahash string
}
