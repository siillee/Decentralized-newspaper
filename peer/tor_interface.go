package peer

import (
	"crypto/rsa"

	"go.dedis.ch/cs438/types"
)

type Tor interface {

	/*
		Returns the directory of a node.
	*/
	GetDirectory() map[string]*rsa.PublicKey

	/*
		Creates a new, random circuit in the network, enabling a node to send messages anonymously.
		The initiating node, called the proxy node in the code, establishes a shared secret key with every node
		in the circuit being created (3 nodes total). It does so with the Diffie-Hellman key exchange protocol,
		establishing a key with the first node, then sending the necessary parameters to the second node, and
		finally the third node. The proxy node sends the parameters encrypted with shared keys of the nodes with
		whom it already did the exchange (sending the parameters to second node encrypted with shared key of the
		first node, so it can decrypt and forward where necessary, etc.).
	*/
	CreateRandomCircuit() (*types.ProxyCircuit, error)

	/*
		Anonymously publishes a summary of an article (an ArticleSummaryMessage).
		The node which wants to anonymously publish an article creates a new circuit,
		and sends the article through the circuit. The exit node of the circuit is the one who
		broadcasts the article, and seems like the author of the article to the whole network.
	*/
	AnonymousPublishArticle(article types.ArticleSummaryMessage, content string) error

	/*
		Anonymously download an article with certain title and metahash.
		The node which wants to anonymously download an article creates a new circuit,
		and sends the download request.The exit node of the circuit downloads the article,
		and then sends it back through the circuit, where it reaches the original node at the end.
	*/
	AnonymousDownloadArticle(title, metahash string) ([]byte, error)
}
