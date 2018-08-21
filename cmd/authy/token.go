package authy

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

type Token struct {
	nonce      string
	privateKey string
}

func MakeToken(encodedNonce, privKey string) *Token {
	return &Token{
		nonce:      encodedNonce,
		privateKey: privKey,
	}
}

func (token *Token) Encode() string {
	sha1Hash := sha1.New()
	sha1Hash.Sum([]byte(token.nonce))

	tokenStr := fmt.Sprintf("%s:%s", token.nonce, token.privateKey)

	return fmt.Sprintf("%x", sha256.Sum256([]byte(tokenStr)))
}
