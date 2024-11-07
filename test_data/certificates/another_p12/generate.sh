#!/bin/bash

# Generate the root key
openssl genpkey -algorithm ED25519 -out root.key

# Generate the root certificate
openssl req -x509 -key root.key -out root.crt -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=foo.com"

# Generate the intermediate key
openssl genpkey -algorithm ED25519 -out intermediate.key

# Create the intermediate certificate signing request
openssl req -new -key intermediate.key -out intermediate.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=intermediate.foo.com"

# Sign the intermediate certificate with the root certificate
openssl x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out intermediate.crt

# Generate the server key
openssl genpkey -algorithm ED25519 -out server.key

# Create the server certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=server.foo.com"

# Sign the server certificate with the intermediate certificate
openssl x509 -req -in server.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out server.crt

# Create the PKCS12 file
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile intermediate.crt -password pass:secret