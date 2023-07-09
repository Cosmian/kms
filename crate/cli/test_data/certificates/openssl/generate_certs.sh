#!/bin/sh

set -euE

# Generate self-signed root certificate
gen_custom() {
  algo=$1
  openssl genpkey -algorithm $algo -out $algo-private-key.pem
  openssl pkey -in $algo-private-key.pem -pubout -out $algo-public-key.pem
  openssl req -new -x509 -key $algo-private-key.pem -out $algo-cert.pem -days 360 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=ROOT-CA-$algo"
}

gen_ec_cert() {
  curve=$1
  # generate a private key for a curve
  openssl ecparam -name $curve -genkey -noout -out $curve-private-key.pem
  # generate corresponding public key
  openssl ec -in $curve-private-key.pem -pubout -out $curve-public-key.pem
  # optional: create a certificate signed by ROOT-CA
  openssl req -new -x509 -key $curve-private-key.pem -out $curve-cert.pem -days 360 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.$curve-example.com"
}

# Generate non standard ED25519 certificate
gen_custom ED25519

# Generate elliptic curve certificates
gen_ec_cert prime192v1
gen_ec_cert secp224r1
gen_ec_cert prime256v1
gen_ec_cert secp384r1

# Generate RSA certificate
openssl req -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.RSA-example.com" -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout rsa-private-key.pem -out rsa-cert.pem
