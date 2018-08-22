package authy

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
)

// Nonce is the non-hashed value passed in an authenticated request, and
// contains information to determine if the request is expired or not.
// The Nonce value expires to deter copycat attacks.
type Nonce struct {
	requestTime    time.Time
	expirationTime time.Time
	publicKey      string
}

// MakeNonce constructs a new Nonce using a given request time, duration, and
// public key. The duration is added to the request time to get the expiration
// time.
func MakeNonce(requestTime time.Time, duration time.Duration, pubKey string) *Nonce {
	return &Nonce{
		requestTime:    requestTime,
		expirationTime: requestTime.Add(duration),
		publicKey:      pubKey,
	}
}

// MakeNonceWithUnixTime creates a new Nonce, but accepts times given in Unix
// Epoch format.
func MakeNonceWithUnixTime(requestUnixTime int64, durationUnix int64, pubKey string) *Nonce {
	requestTime := time.Unix(requestUnixTime, 0)
	expirationTime := time.Unix(requestUnixTime+durationUnix, 0)

	return &Nonce{
		requestTime:    requestTime,
		expirationTime: expirationTime,
		publicKey:      pubKey,
	}
}

// Encode returns a base64 encoded string of a Nonce's three values
func (nonce *Nonce) Encode() string {
	var (
		requestTimeString    string
		expirationTimeString string
		nonceStr             string
		nonceBytes           []byte
	)

	requestTimeString = strconv.FormatInt(nonce.requestTime.Unix(), 10)
	expirationTimeString = strconv.FormatInt(nonce.expirationTime.Unix(), 10)

	nonceStr = fmt.Sprintf("%s:%s:%s", requestTimeString, expirationTimeString, nonce.publicKey)
	nonceBytes = []byte(nonceStr)

	return base64.StdEncoding.EncodeToString(nonceBytes)
}
