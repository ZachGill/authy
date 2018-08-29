package authy

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// NonceHeader should always be used to add or check the nonce in a request
	// instead of X-Authentication-Nonce, to ensure consistency.
	NonceHeader = "X-Authentication-Nonce"
	// TokenHeader should likewise always be used in place of
	// X-Authentication-Token to ensure consistency
	TokenHeader = "X-Authentication-Token"
)

// AuthHandler ensures that HTTP requests contain a valid nonce and token using
// the correct format for nonces and tokens and a map of public to private keys
type AuthHandler struct {
	NextHandler http.Handler
	Keys        map[string]string
}

// NewHandler constructs a new AuthHandler object with a given next handler and
// keys map
func NewHandler(next http.Handler, keys map[string]string) http.Handler {
	return &AuthHandler{
		NextHandler: next,
		Keys:        keys,
	}
}

// ServeHTTP confirms that an HTTP request contains a valid nonce and token
func (middleware *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		nonce            string
		decodedNonce     string
		nonceProperties  []string
		nonceRequestTime int64
		nonceExpiration  int64
		token            string
		serverToken      *Token
	)
	if length := len(r.Header.Get(NonceHeader)); length != 0 {
		nonce = r.Header.Get(NonceHeader)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Request does not contain a nonce"))
		return
	}

	if length := len(r.Header.Get(TokenHeader)); length != 0 {
		token = r.Header.Get(TokenHeader)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Request does not contain a token"))
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
		w.Write([]byte("400 - Request nonce does not contain 3 parameters"))
		return
	}

	if nonceRequestTime, err = strconv.ParseInt(nonceProperties[0], 10, 64); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("400 - Request nonce request time is not in the correct Unix format"))
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
		w.Write([]byte("401 - Request nonce is expired"))
		return
	}

	// Reject a request where the nonce expires greater than 10 seconds after the
	// request time in order to make request spoofing more difficult.
	if (nonceExpiration - nonceRequestTime) > 10 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Request nonce expiration time is greater than ten seconds after request time"))
		return
	}

	// Create our own token with the nonce and private key, then compare it to the token we received
	serverToken = MakeToken(nonce, middleware.Keys[nonceProperties[2]])

	if serverToken.Encode() != token {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("401 - Request contains invalid token (most likely an invalid private key)"))
		return
	}

	middleware.NextHandler.ServeHTTP(w, r)
}
