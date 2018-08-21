package authy

import (
	"net/http"
	"time"
)

// AuthenticateRequest creates a nonce and a token from the input keys, time,
// and duration, and then adds the corresponding headers to an http request
func AuthenticateRequest(pubKey, privKey string, requestTime time.Time, duration time.Duration, r *http.Request) {
	var (
		nonce *Nonce
		token *Token
	)

	nonce = MakeNonce(requestTime, duration, pubKey)
	token = MakeToken(nonce.Encode(), privKey)

	r.Header.Set(NonceHeader, nonce.Encode())
	r.Header.Set(TokenHeader, token.Encode())
}
