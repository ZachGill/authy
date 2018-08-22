package authy_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ZachGill/authy/cmd/authy"
	"github.com/stretchr/testify/assert"
)

type authMiddlewareTestCase struct {
	name               string
	middleware         http.Handler
	requestTime        time.Time
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
		requestTime:        time.Now(),
		expectedStatusCode: 200,
		expectedRespBody:   "OK",
	},
	{
		name:               "bad token (bad private key)",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPirateKey"}),
		requestTime:        time.Now(),
		expectedStatusCode: 401,
		expectedRespBody:   "401 - Request contains invalid token (most likely an invalid private key)",
	},
	{
		name:               "nonce expired",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"}),
		requestTime:        time.Unix(1000000000, 0),
		expectedStatusCode: 401,
		expectedRespBody:   "401 - Request nonce is expired",
	},
}

func TestAuthMiddleware(t *testing.T) {
	for _, testCase := range authMiddlewareTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			var (
				err error
				req *http.Request
			)

			if req, err = http.NewRequest("GET", "http://localhost", bytes.NewBuffer([]byte{})); err != nil {
				t.Fatalf("Error creating HTTP request: %s", err.Error())
			}
			authy.AuthenticateRequest("testPublicKey", "testPrivateKey", testCase.requestTime, 5*time.Second, req)

			rr := httptest.NewRecorder()

			testCase.middleware.ServeHTTP(rr, req)
			assert.Equal(t, testCase.expectedStatusCode, rr.Code)
			assert.Equal(t, testCase.expectedRespBody, rr.Body.String())
		})
	}
}
