package authy_test

import (
	"testing"

	"github.com/ZachGill/authy/cmd/authy"
	"github.com/stretchr/testify/assert"
)

type tokenTestCase struct {
	name                 string
	nonce                *authy.Nonce
	privKey              string
	expectedEncodedToken string
}

var tokenTestCases = []tokenTestCase{
	{
		name:                 "good",
		nonce:                authy.MakeNonceWithUnixTime(1534798931, 5, "testPublicKey"),
		privKey:              "testPrivateKey",
		expectedEncodedToken: "ba2d0ea0b47bc119cee29d5df8165ac0320f0cfe4816480edb0aef5744e3dd0d",
	},
}

func TestToken(t *testing.T) {
	for _, testCase := range tokenTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			testToken := authy.MakeToken(testCase.nonce.Encode(), testCase.privKey)
			assert.Equal(t, testCase.expectedEncodedToken, testToken.Encode())
		})
	}
}
