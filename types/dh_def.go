package types

import "math/big"

type DHPublicKeyMessage struct {
	UserID    string
	PublicKey *big.Int
	//Signature []byte TODO: add signature to content, DH must work together with authentication
}
