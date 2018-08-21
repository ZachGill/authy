package authy_test

import (
	"testing"
	"time"

	"github.com/ZachGill/authy/cmd/authy"
	"github.com/stretchr/testify/assert"
)

type nonceTestCase struct {
	name                 string
	requestTime          time.Time
	duration             time.Duration
	pubKey               string
	expectedEncodedNonce string
}

var nonceTestCases = []nonceTestCase{
	{
		name:                 "good",
		requestTime:          time.Unix(1534798931, 0),
		duration:             5 * time.Second,
		pubKey:               "testPublicKey",
		expectedEncodedNonce: "MTUzNDc5ODkzMToxNTM0Nzk4OTM2OnRlc3RQdWJsaWNLZXk=",
	},
}

func TestNonce(t *testing.T) {
	for _, testCase := range nonceTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			testNonce := authy.MakeNonce(testCase.requestTime, testCase.duration, testCase.pubKey)
			assert.Equal(t, testCase.expectedEncodedNonce, testNonce.Encode())
		})
	}
}

type nonceUnixTestCase struct {
	name                 string
	requestTime          int64
	duration             int64
	pubKey               string
	expectedEncodedNonce string
}

var nonceUnixTestCases = []nonceUnixTestCase{
	{
		name:                 "good",
		requestTime:          1534798931,
		duration:             5,
		pubKey:               "testPublicKey",
		expectedEncodedNonce: "MTUzNDc5ODkzMToxNTM0Nzk4OTM2OnRlc3RQdWJsaWNLZXk=",
	},
}

func TestNonceUnix(t *testing.T) {
	for _, testCase := range nonceUnixTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			testNonce := authy.MakeNonceWithUnixTime(testCase.requestTime, testCase.duration, testCase.pubKey)
			assert.Equal(t, testCase.expectedEncodedNonce, testNonce.Encode())
		})
	}
}
