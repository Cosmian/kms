#!/bin/bash

OPENSSL="$HOME/homebrew/bin/openssl"

# Generate the ca key
$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key

# Generate the ca certificate
$OPENSSL req -x509 -key ca.key -out ca.crt -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=foo.com"

## Generate the intermediate key
#$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out intermediate.key
#
## Create the intermediate certificate signing request
#$OPENSSL req -new -key intermediate.key -out intermediate.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=intermediate.foo.com"
#
## Sign the intermediate certificate with the ca certificate
#$OPENSSL x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out intermediate.crt

# Generate the server key
$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key

# Create the server certificate signing request
$OPENSSL req -new -key server.key -out server.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=server.foo.com"

# Sign the server certificate with the ca certificate
$OPENSSL x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Create the PKCS12 file
#$OPENSSL pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile ca.crt -password pass:secret

# Generate the client key
$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key

# Create the client certificate signing request
$OPENSSL req -new -key client.key -out client.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=client.foo.com"

# Sign the client certificate with the intermediate certificate
$OPENSSL x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
