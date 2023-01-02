package types

import "fmt"

// -----------------------------------------------------------------------------
// DHPublicKeyMessage

// NewEmpty implements types.Message.
func (d DHPublicKeyMessage) NewEmpty() Message {
	return &DHPublicKeyMessage{}
}

// Name implements types.Message.
func (d DHPublicKeyMessage) Name() string {
	return "DHPublicKey"
}

// String implements types.Message.
func (d DHPublicKeyMessage) String() string {
	return fmt.Sprintf("DHPublicKey{%s %x}", d.UserID, d.PublicKey)
}

// HTML implements types.Message.
func (d DHPublicKeyMessage) HTML() string {
	return d.String()
}
