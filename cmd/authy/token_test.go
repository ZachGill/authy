package authy_test

import "github.com/ZachGill/authy/cmd/authy"

type tokenTestCase struct {
	name                 string
	nonce                *authy.Nonce
	privKey              string
	expectedToken        *authy.Token
	expectedEncodedToken string
}

var tokenTestCases = []tokenTestCase{
	{
		name:  "good",
		nonce: makeNonce(),
	},
}
