package peer

import "go.dedis.ch/cs438/types"

type Tor interface {

	// Returns the directory of a node.
	GetDirectory() map[string]types.TorNode

	// Creates a new, random circuit in the network, enabling a node to send messages anonymously.
	CreateRandomCircuit() (*types.ProxyCircuit, error)

	// Anonymously publishes a summary of an article (an ArticleSummaryMessage).
	SendAnonymousArticleSummaryMessage(article types.ArticleSummaryMessage) error

	// Anonymously download an article with certain title and metahash.
	SendAnonymousDownloadRequestMessage(title, metahash string) error
}
