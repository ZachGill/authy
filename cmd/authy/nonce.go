package authy

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
)

type Nonce struct {
	requestTime    time.Time
	expirationTime time.Time
	publicKey      string
}

func MakeNonce(requestTime time.Time, duration time.Duration, pubKey string) *Nonce {
	return &Nonce{
		requestTime:    requestTime,
		expirationTime: requestTime.Add(duration),
		publicKey:      pubKey,
	}
}

func MakeNonce(requestUnixTime int64, durationUnix int64, pubKey string) *Nonce {
	requestTime := time.Unix(requestUnixTime, 0)
	expirationTime := time.Unix(requestUnixTime+durationUnix, 0)

	return &Nonce{
		requestTime:    requestTime,
		expirationTime: requestTime.Add(duration),
		publicKey:      pubKey,
	}
}

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
