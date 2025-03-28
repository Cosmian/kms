#!/bin/bash

# on MacOS, you should pass a link to an actually installed openssl binary, and nopt use the default `libressl`
# which generates PKCS12 files qith the deprecated RC2 algorithm
OPENSSL_BIN=${1:-openssl}

# Generate CA private key
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key

# Generate self-signed CA certificate
$OPENSSL_BIN req -new -x509 -days 3650 -key ca.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=Acme Test Root CA" -out ca.crt


## Server Cert

# Generate private key for kmserver.acme.com
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kmserver.acme.com.key

# Generate certificate signing request for kmserver.acme.com
$OPENSSL_BIN req -new -key kmserver.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kmserver.acme.com" -out kmserver.acme.com.csr

# Generate certificate for kmserver.acme.com signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in kmserver.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out kmserver.acme.com.crt

# Generate a PKCS12 file
$OPENSSL_BIN pkcs12 -export -out kmserver.acme.com.p12 -inkey kmserver.acme.com.key -in kmserver.acme.com.crt -certfile ca.crt -password pass:password


## "owner" client cert

# Generate private key for owner.client.acme.com
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out owner.client.acme.com.key

# Generate certificate signing request for owner.client.acme.com
$OPENSSL_BIN req -new -key owner.client.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=owner.client@acme.com" -out owner.client.acme.com.csr

# Generate certificate for owner.client.acme.com signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in owner.client.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out owner.client.acme.com.crt

# Generate a PKCS12 file
$OPENSSL_BIN pkcs12 -export -out owner.client.acme.com.p12 -inkey owner.client.acme.com.key -in owner.client.acme.com.crt -certfile ca.crt -password pass:password


## "user" client cert

# Generate private key for user.client.acme.com
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out user.client.acme.com.key

# Generate certificate signing request for user.client.acme.com
$OPENSSL_BIN req -new -key user.client.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=user.client@acme.com" -out user.client.acme.com.csr

# Generate certificate for user.client.acme.com signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in user.client.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.client.acme.com.crt

# Generate a PKCS12 file
$OPENSSL_BIN pkcs12 -export -out user.client.acme.com.p12 -inkey user.client.acme.com.key -in user.client.acme.com.crt -certfile ca.crt -password pass:password

