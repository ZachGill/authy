package authy

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

type Token struct {
	nonce      Nonce
	privateKey string
}

func MakeToken(nonce Nonce, privKey string) *Token {
	return &Token{
		nonce:      nonce,
		privateKey: privKey,
	}
}

func (token *Token) Encode() string {
	encodedNonce := token.nonce.Encode()

	sha1Hash := sha1.New()
	sha1Hash.Sum([]byte(encodedNonce))

	tokenStr := fmt.Sprintf("%s:%s", encodedNonce, token.privateKey)

	sha256Hash := sha256.New()
	return string(sha256Hash.Sum([]byte(tokenStr)))
}
