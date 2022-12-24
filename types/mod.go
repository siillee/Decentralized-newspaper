package types

import (
	"encoding/json"
	"go.dedis.ch/cs438/transport"
)

// Message defines the type of message that can be marshalled/unmarshalled over
// the network.
type Message interface {
	NewEmpty() Message
	Name() string
	String() string
	HTML() string
}

func ToTransport(m Message) (transport.Message, error) {
	buf, err := json.Marshal(&m)
	if err != nil {
		return transport.Message{}, err
	}
	return transport.Message{
		Type:    m.Name(),
		Payload: buf,
	}, nil
}
