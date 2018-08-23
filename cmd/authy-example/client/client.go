package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/ZachGill/authy/cmd/authy"
)

func main() {
	var err error
	// Valid
	if err = makeAuthRequest("testPublicKey", "testPrivateKey"); err != nil {
		log.Println("Error making valid request:", err.Error())
	}
	// Invalid
	if err = makeAuthRequest("testPublicKey", "testPirateKey"); err != nil {
		log.Println("Error making invalid request:", err.Error())
	}
}

func makeAuthRequest(public, private string) error {
	var (
		err        error
		client     = &http.Client{}
		authReq    *http.Request
		requestURL string
		resp       *http.Response
		bodyBytes  []byte
	)
	requestURL = "http://localhost:8080"

	if authReq, err = http.NewRequest("GET", requestURL, nil); err != nil {
		return err
	}

	// authReq.Host = ":8080"

	authy.AuthenticateRequest(public, private, time.Now(), 5*time.Second, authReq)

	if resp, err = client.Do(authReq); err != nil {
		return err
	}
	defer resp.Body.Close()

	fmt.Println(resp.StatusCode)
	if bodyBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return err
	}
	fmt.Println(string(bodyBytes))
	return err
}
