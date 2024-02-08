#!/bin/sh

# Generate a test RSA key in PKCS8 to use with the ms_dke tests.
openssl genpkey -algorithm RSA -out private_key.pkcs8.pem -pkeyopt rsa_keygen_bits:2048

# Generate a PKCS#8 public key from the PKCS8 private key.
openssl pkey -in private_key.pkcs8.pem -pubout -out public_key.pkcs8.pem

# Convert the private key to PKCS1 format for use with the ms_dke tests.
openssl rsa -in private_key.pkcs8.pem -out private_key.pkcs1.pem -traditional

# Generate a PKCS#1 public key from the PKCS1 private key.
openssl rsa -in private_key.pkcs1.pem --traditional -pubout -out public_key.pkcs1.pem -RSAPublicKey_out
