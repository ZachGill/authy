package authy

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

// Token is the hashed value in an authenticated request, and contains a nonce
// and a private key. Token needs a nonce so that the server can validate not
// just that the private key is valid, but also that the hashed value is from a
// non-expired request.
type Token struct {
	nonce      string
	privateKey string
}

// MakeToken accepts the base64 encoded value of a Nonce and a private key and
// creates a new Token object.
func MakeToken(encodedNonce, privKey string) *Token {
	return &Token{
		nonce:      encodedNonce,
		privateKey: privKey,
	}
}

// Encode returns a sha256 hashed string of a Token's values
func (token *Token) Encode() string {
	sha1Hash := sha1.New()
	sha1Hash.Sum([]byte(token.nonce))

	tokenStr := fmt.Sprintf("%s:%s", token.nonce, token.privateKey)

	return fmt.Sprintf("%x", sha256.Sum256([]byte(tokenStr)))
}
