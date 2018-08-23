package main

import "net/http"

// Healthcheck is used to ensure that the service is running properly
type Healthcheck struct {
	message string
}

// ServeHTTP returns a Healthcheck's message parameter in the response body and
// writes a 200 response code to the response header.
func (handler *Healthcheck) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(handler.message))
	return
}
