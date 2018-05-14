# CA-Auth-Server
The certificate authority validation system

This code does the following:
1. First it generates a CA certificate using the openssl CLI tool, then stores the cert and key in ca.pem and ca.key respectively. This is currently done via the makefile for testing, but will shortly be added as a feature when this is made into a fully running server.
2. In the actual code, the OpenSSL api is used to do the following:
- Generate a private RSA key.
- Generate a Certificate Signing Request (CSA)
- Sign the request using the generated CA certificate.
3. The program will then send the generated private key and signed certificate in PEM format, and it will also store it in the servers database for use with later requests.


## Compiling
### Requirements
- OpenSSL
- Python 3
- Docker

### Instructions
`$ cd auth/`

`$ make`

`$ ./cert ca.key ca.pem`

The results should print to either stderr or stdout in the console.
