package authy

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	NonceHeader = "X-Authentication-Nonce"
	TokenHeader = "X-Authentication-Token"
)

type AuthHandler struct {
	NextHandler http.Handler
	Keys        map[string]string
}

func NewHandler(next http.Handler, keys map[string]string) http.Handler {
	return &AuthHandler{
		NextHandler: next,
		Keys:        keys,
	}
}

// ServeHTTP adds a header with a transaction ID before calling the next handler
func (middleware *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		nonce           string
		decodedNonce    string
		nonceProperties []string
		nonceExpiration int64
		token           string
		serverToken     *Token
	)
	if length := len(r.Header.Get(NonceHeader)); length == 1 {
		nonce = r.Header.Get(NonceHeader)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		if length == 0 {
			w.Write([]byte("409 - Request does not contain a nonce"))
			return
		}

		w.Write([]byte("409 - Request contains more than one nonce"))
		return
	}

	if length := len(r.Header.Get(TokenHeader)); length == 1 {
		nonce = r.Header.Get(TokenHeader)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		if length == 0 {
			w.Write([]byte("409 - Request does not contain a token"))
			return
		}

		w.Write([]byte("409 - Request contains more than one token"))
		return
	}

	// Decode the Base64 encoded nonce into a byte array
	decodedNonceByteStr, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("400 - Request nonce is not base 64 encoded"))
		return
	}

	// Convert the nonce byte array to a string and split it into its components
	decodedNonce = string(decodedNonceByteStr)
	nonceProperties = strings.Split(decodedNonce, ":")
	if len(nonceProperties) != 3 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("409 - Request does not contain a request time"))
		return
	}

	// Check if the nonce is expired, reject if current time is greater than expiration
	if nonceExpiration, err = strconv.ParseInt(nonceProperties[1], 10, 64); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("400 - Request nonce expiration time is not in the correct Unix format"))
		return
	}

	if time.Now().Unix() > nonceExpiration {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("409 - Request nonce is expired"))
		return
	}

	// Create our own token with the nonce and private key, then compare it to the token we received
	serverToken = MakeToken(nonce, middleware.Keys[nonceProperties[2]])

	if serverToken.Encode() != token {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("409 - Request contains invalid token (most likely an invalid private key)"))
		return
	}

	middleware.NextHandler.ServeHTTP(w, r)
}
