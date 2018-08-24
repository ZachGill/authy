# authy-example

auth-example provides an example client and server using authy for request authentication.


### Server
The server starts an HTTP server with a handler for the root path that returns a 200 status code when requests make it through, but those requests must first be authenticated by authy's middleware.

### Client
Likewise, the client sends authenticated HTTP requests to the server, one with a correct private key and one with an incorrect private key.

If the middleware and request authenticator are working, the valid key request should return a 200 status code and the invalid should return a 401 status code.