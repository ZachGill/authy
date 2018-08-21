package authy_test

import (
	"net/http"

	"github.com/ZachGill/authy/cmd/authy"
)

type authMiddlewareTestCase struct {
	name               string
	middleware         http.Handler
	expectedStatusCode int
	expectedRespBody   string
}

type testHandler struct {
	response []byte
}

func (handler *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write(handler.response)
	return
}

var authMiddlewareTestCases = []authMiddlewareTestCase{
	{
		name:               "good",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"}),
		expectedStatusCode: 200,
		expectedRespBody:   "OK",
	},
}
