# Authy

Authy is a simple client- and server-side library for authenticating HTTP requests. It works using public and private API keys shared between the client and server.

## Using Authy

Authy can be used in the following two ways:

1. To add API auth to an HTTP request:
    
    * Use `authy.AuthenticateRequest()` to add a nonce and a token to the headers of an `http.Request` object

2. To authenticate incoming HTTP requests made with Authy:

    * Authy includes a middleware authentication handler, which accepts a map of public to private keys. Authy will reject any requests with incorrect authentication.

## How Authy Works

Authy creates both a nonce and token value for each HTTP request it adds authentication to.

### Nonce
The nonce contains the time the request it's attached to was sent, when it expires, and the public API key of the user sending the request. The nonce is included in the request headers as a base64-encoded string. Decoded, a nonce looks something like this:

`1500000000:1500000005:test_api_key`

### Token
The token is a sha256 hash of the encoded nonce and the private API key. Private keys are always hashed so as to make it (nearly) impossible for someone capturing API requests to be able to collect the raw private key.

### Validation
Authy's middleware is where these values are then authenticated. The middleware first decodes the nonce and ensures that it follows the proper format and is not expired, then creates a token in the same way that the request authenticator does to ensure that the generated token and the received token match.

This requires that both the client and server know the public-private key pair, meaning that these values must be shared before any request can be sent.

## Contributing?

Please submit an issue if you have any suggestions or find problems/bugs in the code. Feel free to submit a pull request as well.