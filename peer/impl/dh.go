package impl

import (
	rd "crypto/rand"
	"math/big"

	"golang.org/x/xerrors"
)

func (n *node) DHGenerateKeys() (*big.Int, *big.Int) {

	privateKey := new(big.Int).SetInt64(0)
	myPublicKey := new(big.Int).SetInt64(0)
	privateKey, _ = rd.Int(rd.Reader, n.conf.DH.Q)

	myPublicKey.Exp(n.conf.DH.G, privateKey, n.conf.DH.P)

	return privateKey, myPublicKey
}

func (n *node) DHComputeSharedKey(privateKey, publicKey *big.Int) (*big.Int, error) {

	// check group membership (avoids MITM attacks)
	one := new(big.Int).SetInt64(1)
	if publicKey.Cmp(one) <= 0 || publicKey.Cmp(n.conf.DH.P) >= 0 {
		return nil, xerrors.Errorf("[%s] dh public key has invalid format (wrong range)", n.GetAddress())
	}
	checkPK := new(big.Int).SetInt64(0)
	checkPK.Exp(publicKey, n.conf.DH.Q, n.conf.DH.P)
	if checkPK.Cmp(one) != 0 {
		return nil, xerrors.Errorf("[%s] dh public key has invalid format (wrong order)", n.GetAddress())
	}

	//compute shared secret
	secret := new(big.Int).SetInt64(0)
	secret.Exp(publicKey, privateKey, n.conf.DH.P)

	return secret, nil
}
