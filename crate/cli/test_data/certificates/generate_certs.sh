#!/bin/bash

# Generate CA private key
openssl genpkey -algorithm RSA -out ca.key

# Generate self-signed CA certificate
openssl req -new -x509 -days 3650 -key ca.key -subj "/C=FR/ST=IdF/L=Paris/O=CosmianTest/CN=Cosmian Test Root CA" -out ca.crt


## Server Cert

# Generate private key for kmserver.cosmian.com
openssl genpkey -algorithm RSA -out kmserver.cosmian.com.key

# Generate certificate signing request for kmserver.cosmian.com
openssl req -new -key kmserver.cosmian.com.key -subj "/C=FR/ST=IdF/L=Paris/O=CosmianTest/CN=kmserver.cosmian.com" -out kmserver.cosmian.com.csr

# Generate certificate for kmserver.cosmian.com signed by our own CA
openssl x509 -req -days 3650 -in kmserver.cosmian.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out kmserver.cosmian.com.crt

# Generate PKCS12 file without password
openssl pkcs12 -export -out kmserver.cosmian.com.p12 -inkey kmserver.cosmian.com.key -in kmserver.cosmian.com.crt -certfile ca.crt


## Client cert

# Generate private key for client.cosmian.com
openssl genpkey -algorithm RSA -out client.cosmian.com.key

# Generate certificate signing request for client.cosmian.com
openssl req -new -key client.cosmian.com.key -subj "/C=FR/ST=IdF/L=Paris/O=CosmianTest/CN=test.client@cosmian.com" -out client.cosmian.com.csr

# Generate certificate for client.cosmian.com signed by our own CA
openssl x509 -req -days 3650 -in client.cosmian.com.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.cosmian.com.crt
