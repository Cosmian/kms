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

gen_revoked_cert() {
  curve=$1
  # generate a private key for a curve
  openssl ecparam -name $curve -genkey -noout -out $curve-revoked.key
  #Create cert signing request for the private key
  openssl req -new -key $curve-revoked.key -out $curve-revoked.csr -subj "/C=FR/ST=IdF/L=Paris/O=CosmianTemp/CN=$curve revoked certificate server"
  #Sign the leaf.csr using ca.crt
  openssl x509 -req -in $curve-revoked.csr -out $curve-revoked.crt -days 365 -CAcreateserial -CA $curve-cert.pem -CAkey $curve-private-key.pem -CAserial serial -extfile ext.cnf

  openssl ca -config openssl.cnf -revoke $curve-revoked.crt -keyfile $curve-private-key.pem -cert $curve-cert.pem
  openssl ca -config openssl.cnf -gencrl -keyfile $curve-private-key.pem -cert $curve-cert.pem -out $curve.crl
  scp $curve.crl cosmian@package.cosmian.com:/mnt/package/kms/
}

gen_rsa() {
  size=$1
  openssl req -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.RSA-$size-example.com" -new -newkey rsa:$size -sha256 -days 365 -nodes -x509 -keyout rsa-$size-private-key.pem -out rsa-$size-cert.pem
}

# Generate non standard ED25519 certificate
gen_custom ED25519

# Generate elliptic curve certificates
gen_ec_cert prime192v1
gen_ec_cert secp224r1
gen_ec_cert prime256v1
gen_ec_cert secp384r1
gen_ec_cert secp521r1

# Generate revoked certificate
gen_revoked_cert prime256v1

# Generate RSA certificate
gen_rsa 2048
gen_rsa 3072
gen_rsa 4096
