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
	duration           time.Duration
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
		duration:           5 * time.Second,
		expectedStatusCode: 200,
		expectedRespBody:   "OK",
	},
	{
		name:               "bad token (bad private key)",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPirateKey"}),
		requestTime:        time.Now(),
		duration:           5 * time.Second,
		expectedStatusCode: 401,
		expectedRespBody:   "401 - Request contains invalid token (most likely an invalid private key)",
	},
	{
		name:               "nonce expired",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"}),
		requestTime:        time.Unix(1000000000, 0),
		duration:           5 * time.Second,
		expectedStatusCode: 401,
		expectedRespBody:   "401 - Request nonce is expired",
	},
	{
		name:               "nonce expiration duration too long",
		middleware:         authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"}),
		requestTime:        time.Now(),
		duration:           12 * time.Second,
		expectedStatusCode: 401,
		expectedRespBody:   "401 - Request nonce expiration time is greater than ten seconds after request time",
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
			authy.AuthenticateRequest("testPublicKey", "testPrivateKey", testCase.requestTime, testCase.duration, req)

			rr := httptest.NewRecorder()

			testCase.middleware.ServeHTTP(rr, req)
			assert.Equal(t, testCase.expectedStatusCode, rr.Code)
			assert.Equal(t, testCase.expectedRespBody, rr.Body.String())
		})
	}
}

func TestMiddleware_MissingParams(t *testing.T) {
	t.Run("Missing Token", func(t *testing.T) {
		var (
			err        error
			req        *http.Request
			middleware = authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"})
		)

		if req, err = http.NewRequest("GET", "http://localhost", bytes.NewBuffer([]byte{})); err != nil {
			t.Fatalf("Error creating HTTP request: %s", err.Error())
		}

		req.Header.Add(authy.TokenHeader, "test")

		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "401 - Request does not contain a nonce", rr.Body.String())

		if req, err = http.NewRequest("GET", "http://localhost", bytes.NewBuffer([]byte{})); err != nil {
			t.Fatalf("Error creating HTTP request: %s", err.Error())
		}

		req.Header.Add(authy.NonceHeader, "test")

		rr = httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "401 - Request does not contain a token", rr.Body.String())
	})
}

type authMiddlewareBadParamTestCase struct {
	name               string
	nonce              string
	token              string
	expectedStatusCode int
	expectedRespBody   string
}

var authMiddlewareBadParamTestCases = []authMiddlewareBadParamTestCase{
	{
		name:               "nonce not base64 encoded",
		nonce:              "&&%%^^",
		token:              "doesntmatter",
		expectedStatusCode: 400,
		expectedRespBody:   "400 - Request nonce is not base 64 encoded",
	},
	{
		name:               "nonce does not contain three properties",
		nonce:              "MToy", // "1:2"
		token:              "doesntmatter",
		expectedStatusCode: 400,
		expectedRespBody:   "400 - Request nonce does not contain 3 parameters",
	},
	{
		name:               "nonce request time is not unix format",
		nonce:              "ZGF0ZToyOjM=", // "date:2:3"
		token:              "doesntmatter",
		expectedStatusCode: 400,
		expectedRespBody:   "400 - Request nonce request time is not in the correct Unix format",
	},
	{
		name:               "nonce expiration time is not unix format",
		nonce:              "MTpkYXRlOjM=", // "1:date:3"
		token:              "doesntmatter",
		expectedStatusCode: 400,
		expectedRespBody:   "400 - Request nonce expiration time is not in the correct Unix format",
	},
}

func TestAuthMiddleware_BadParams(t *testing.T) {
	for _, testCase := range authMiddlewareBadParamTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			var (
				err        error
				req        *http.Request
				middleware = authy.NewHandler(&testHandler{response: []byte("OK")}, map[string]string{"testPublicKey": "testPrivateKey"})
			)

			if req, err = http.NewRequest("GET", "http://localhost", bytes.NewBuffer([]byte{})); err != nil {
				t.Fatalf("Error creating HTTP request: %s", err.Error())
			}

			req.Header.Add(authy.NonceHeader, testCase.nonce)
			req.Header.Add(authy.TokenHeader, testCase.token)

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			assert.Equal(t, testCase.expectedStatusCode, rr.Code)
			assert.Equal(t, testCase.expectedRespBody, rr.Body.String())
		})
	}
}
