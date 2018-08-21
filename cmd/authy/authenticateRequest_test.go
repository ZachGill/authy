package authy_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/ZachGill/authy/cmd/authy"
	"github.com/stretchr/testify/assert"
)

type authenticateRequestTestCase struct {
	name          string
	pubKey        string
	privKey       string
	requestTime   time.Time
	duration      time.Duration
	expectedToken string
	expectedNonce string
}

var authenticateRequestTestCases = []authenticateRequestTestCase{
	{
		name:          "good",
		pubKey:        "testPublicKey",
		privKey:       "testPrivateKey",
		requestTime:   time.Unix(1534798931, 0),
		duration:      5 * time.Second,
		expectedToken: "ba2d0ea0b47bc119cee29d5df8165ac0320f0cfe4816480edb0aef5744e3dd0d",
		expectedNonce: "MTUzNDc5ODkzMToxNTM0Nzk4OTM2OnRlc3RQdWJsaWNLZXk=",
	},
}

func TestAuthenticateRequest(t *testing.T) {
	for _, testCase := range authenticateRequestTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			var (
				err error
				req *http.Request
			)
			if req, err = http.NewRequest("GET", "http://localhost", bytes.NewBuffer([]byte{})); err != nil {
				t.Fatalf("Error creating HTTP request: %s", err.Error())
			}
			authy.AuthenticateRequest(testCase.pubKey, testCase.privKey, testCase.requestTime, testCase.duration, req)
			assert.Equal(t, testCase.expectedNonce, req.Header.Get(authy.NonceHeader))
			assert.Equal(t, testCase.expectedToken, req.Header.Get(authy.TokenHeader))
		})
	}
}
