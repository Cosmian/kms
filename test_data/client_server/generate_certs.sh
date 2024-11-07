#!/bin/bash

# Generate CA private key
openssl genpkey -algorithm RSA -out ca.key

# Generate self-signed CA certificate
openssl req -new -x509 -days 3650 -key ca.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=Acme Test Root CA" -out ca.crt


## Server Cert

# Generate private key for kmserver.acme.com
openssl genpkey -algorithm RSA -out kmserver.acme.com.key

# Generate certificate signing request for kmserver.acme.com
openssl req -new -key kmserver.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kmserver.acme.com" -out kmserver.acme.com.csr

# Generate certificate for kmserver.acme.com signed by our own CA
openssl x509 -req -days 3650 -in kmserver.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out kmserver.acme.com.crt

# Generate a PKCS12 file
openssl pkcs12 -export -out kmserver.acme.com.p12 -inkey kmserver.acme.com.key -in kmserver.acme.com.crt -certfile ca.crt -password pass:password


## "owner" client cert

# Generate private key for owner.client.acme.com
openssl genpkey -algorithm RSA -out owner.client.acme.com.key

# Generate certificate signing request for owner.client.acme.com
openssl req -new -key owner.client.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=owner.client@acme.com" -out owner.client.acme.com.csr

# Generate certificate for owner.client.acme.com signed by our own CA
openssl x509 -req -days 3650 -in owner.client.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out owner.client.acme.com.crt

# Generate a PKCS12 file
openssl pkcs12 -export -out owner.client.acme.com.p12 -inkey owner.client.acme.com.key -in owner.client.acme.com.crt -certfile ca.crt -password pass:password


## "user" client cert

# Generate private key for user.client.acme.com
openssl genpkey -algorithm RSA -out user.client.acme.com.key

# Generate certificate signing request for user.client.acme.com
openssl req -new -key user.client.acme.com.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=user.client@acme.com" -out user.client.acme.com.csr

# Generate certificate for user.client.acme.com signed by our own CA
openssl x509 -req -days 3650 -in user.client.acme.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.client.acme.com.crt

# Generate a PKCS12 file
openssl pkcs12 -export -out user.client.acme.com.p12 -inkey user.client.acme.com.key -in user.client.acme.com.crt -certfile ca.crt -password pass:password
