package impl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/xerrors"
)

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, xerrors.Errorf("error while generating new AES cipher for encryption: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, xerrors.Errorf("error while wrapping AES cipher in GCM for encryption: %v", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, xerrors.Errorf("error while generating nonce: %v", err)
	}

	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, xerrors.Errorf("error while generating new AES cipher for decryption: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, xerrors.Errorf("error while wrapping AES cipher in GCM for decryption: %v", err)
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, xerrors.Errorf("wrong size of ciphertext for decryption: %v", err)
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, xerrors.Errorf("error while decryptinh ciphertext: %v", err)
	}

	return plaintext, nil
}
