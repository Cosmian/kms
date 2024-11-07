#!/bin/bash

#####################
# EC
#####################

# Generate a SEC1 EC private key
openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key_sec1.pem

# # Extract the public key from the SEC1 EC private key -> note: this generates a SPKI public key
# openssl ec -in ec_private_key_sec1.pem -pubout -out ec_public_key_sec1.pem

# Generate a PKCS#8 EC private key
openssl pkcs8 -topk8 -nocrypt -in ec_private_key_sec1.pem -out ec_private_key_pkcs8.pem

# Extract the public key from the EC private key
openssl ec -in ec_private_key_pkcs8.pem -pubout -out ec_public_key_spki.pem


#####################
# RSA
#####################

# Generate a PKCS#1 RSA private key. The --traditional flag is now required to generate PKCS#1 keys.
openssl genrsa --traditional -out rsa_private_key_pkcs1.pem

# Extract the public key from the PKCS#1 RSA private key
openssl rsa -in rsa_private_key_pkcs1.pem --traditional -pubout -out rsa_public_key_pkcs1.pem -RSAPublicKey_out

# Generate a PKCS#8 RSA private key from the previous PKCS#1 RSA private key
# openssl genpkey -algorithm RSA -out rsa_private_key_pkcs8.pem
openssl pkcs8 -topk8 -inform pem -in rsa_private_key_pkcs1.pem -out rsa_private_key_pkcs8.pem -nocrypt

# Extract the public key from the RSA private key
openssl rsa -in rsa_private_key_pkcs8.pem -pubout -out rsa_public_key_spki.pem