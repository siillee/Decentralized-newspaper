package customCrypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
)

func SignRSA(privateKey *rsa.PrivateKey, digest []byte) ([]byte, error) {
	k := 256 // modulus of k bytes
	algoID := "sha256WithRSAEncryption"

	//encode the mesage digest and the identifier of the hash algorithm into a string D
	var D bytes.Buffer
	D.WriteString(algoID)
	D.Write(digest)

	//pad D with a zero byte to the left, then with many FF bytes in order to reach a length of k-2 bytes,
	//then with a 01 byte followed by a 00 byte to obtain k bytes
	var y bytes.Buffer
	y.WriteByte(byte(0))
	y.WriteByte(byte(1))
	for i := 0; i < k-D.Len()-3; i++ {
		y.WriteByte(byte(255))
	}
	y.WriteByte(byte(0))
	y.Write(D.Bytes())

	// convert the byte string 00||01||FF...FF||00||D into an integer
	yInt := new(big.Int).SetBytes(y.Bytes())

	// compute the plain RSA signature => signature = y^d mod N
	signature := new(big.Int).SetInt64(0)
	signature.Exp(yInt, privateKey.D, privateKey.PublicKey.N)

	return signature.Bytes(), nil
}

func VerifyRSA(publicKey *rsa.PublicKey, digest, signature []byte) bool {
	k := 256 // modulus of k bytes
	algoID := "sha256WithRSAEncryption"

	// convert the signature into an integer. Reject it if it is greater than the modulus
	x := new(big.Int).SetBytes(signature)
	if x.Cmp(publicKey.N) > 0 {
		fmt.Println("invalid signature: wrong range")
		return false
	}

	//  perform the plain RSA verification and obtain another integer
	z := new(big.Int).SetInt64(0)
	exponent := big.NewInt(int64(publicKey.E))
	z.Exp(x, exponent, publicKey.N)

	// convert back the integer into a byte string
	s := z.Bytes()

	// check thath the string has the 00||01||FF...FF||00||D format for some string D
	var buf bytes.Buffer
	buf.Write(s)

	count := 1 // leading 00 is not read
	b1, _ := buf.ReadByte()
	if b1 != byte(1) {
		fmt.Println("invalid format: leading 01 missing")
		return false
	}
	count++

	b255, _ := buf.ReadByte()
	for b255 == byte(255) {
		b255, _ = buf.ReadByte()
		count++
	}

	b0 := b255
	if b0 != byte(0) {
		fmt.Println("invalid format: missing 00 after FF bytes")
		return false
	}
	count++

	bD := make([]byte, k-count)
	buf.Read(bD)

	stringD := string(bD)
	if !strings.HasPrefix(stringD, algoID) {
		fmt.Println("invalid algoID")
		return false
	}

	messageHash := bD[len(algoID):]

	// check that D contains the same digest
	cmp := bytes.Compare(messageHash, digest)
	return cmp == 0
}
