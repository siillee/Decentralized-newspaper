package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	"go.dedis.ch/cs438/customCrypto"
)

// -----------------------------------------------------------------------------
// ArticleSummaryMessage

// NewEmpty implements types.Message.
func (a ArticleSummaryMessage) NewEmpty() Message {
	return &ArticleSummaryMessage{}
}

// Name implements types.Message.
func (a ArticleSummaryMessage) Name() string {
	return "article-summary"
}

// String implements types.Message.
func (a ArticleSummaryMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "Title: \t %s \n", a.Title)
	fmt.Fprintf(out, "UserID: \t %s \n", a.UserID)
	fmt.Fprintf(out, "Signature: %x \n", a.Signature)

	return out.String()
}

// HTML implements types.Message.
func (a ArticleSummaryMessage) HTML() string {
	return a.String()
}

func (a ArticleSummaryMessage) Hash() []byte {
	h := crypto.SHA256.New()
	h.Write([]byte(a.ArticleID))
	h.Write([]byte(a.UserID))
	h.Write([]byte(a.Title))
	//h.Write([]byte(a.ShortDescription))
	h.Write([]byte(a.Metahash))
	return h.Sum(nil)
}

func (a ArticleSummaryMessage) Sign(privateKey *rsa.PrivateKey) ([]byte, error) {
	return customCrypto.SignRSA(privateKey, a.Hash())
}

func (a ArticleSummaryMessage) Verify(publicKey rsa.PublicKey) bool {
	return customCrypto.VerifyRSA(&publicKey, a.Hash(), a.Signature)
}

// -----------------------------------------------------------------------------
// CommentMessage

// NewEmpty implements types.Message.
func (c CommentMessage) NewEmpty() Message {
	return &CommentMessage{}
}

// Name implements types.Message.
func (c CommentMessage) Name() string {
	return "comment"
}

// String implements types.Message.
func (c CommentMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "%s - [%s] :  %s \n", c.ArticleID, c.UserID, c.Content)

	return out.String()
}

// HTML implements types.Message.
func (c CommentMessage) HTML() string {
	return c.String()
}

func (c CommentMessage) Hash() []byte {
	h := crypto.SHA256.New()
	h.Write([]byte(c.ArticleID))
	h.Write([]byte(c.UserID))
	h.Write([]byte(c.Content))
	return h.Sum(nil)
}

func (c CommentMessage) Sign(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, privateKey, c.Hash())
}

func (c CommentMessage) Verify(publicKey ecdsa.PublicKey) bool {
	return ecdsa.VerifyASN1(&publicKey, c.Hash(), c.Signature)
}

// -----------------------------------------------------------------------------
// VoteMessage

// NewEmpty implements types.Message.
func (v VoteMessage) NewEmpty() Message {
	return &VoteMessage{}
}

// Name implements types.Message.
func (v VoteMessage) Name() string {
	return "vote"
}

// String implements types.Message.
func (v VoteMessage) String() string {
	out := new(strings.Builder)

	fmt.Fprintf(out, "(%s : %s) \n", v.ArticleID, v.UserID)

	return out.String()
}

// HTML implements types.Message.
func (v VoteMessage) HTML() string {
	return v.String()
}

func (v VoteMessage) Hash() []byte {
	h := crypto.SHA256.New()
	h.Write([]byte(v.ArticleID))
	h.Write([]byte(v.UserID))
	return h.Sum(nil)
}

func (v VoteMessage) Sign(privateKey *rsa.PrivateKey) ([]byte, error) {
	return customCrypto.SignRSA(privateKey, v.Hash())
}

func (v VoteMessage) Verify(publicKey rsa.PublicKey) bool {
	return customCrypto.VerifyRSA(&publicKey, v.Hash(), v.Signature)
}
