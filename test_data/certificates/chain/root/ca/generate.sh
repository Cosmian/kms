#!/bin/sh

echo "removing old configurations"
rm -rf certs crl newcerts private intermediate
rm index.*
rm serial*
rm chain_t0.pem
rm chain_t1.pem

set -ex

## making CA Environment

mkdir certs crl newcerts private intermediate

touch index.txt
echo 1000 >serial

## Generating CA
echo "Generating ca key"
openssl genrsa -aes256 -out private/ca.key.pem -passout pass:root123 4096

echo "Generating ca csr"
openssl req -batch -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 \
      -sha256 -extensions v3_ca -out certs/ca.cert.pem -subj "/C=FR/ST=France/L=IDF/O=Cosmian/CN=Root/emailAddress=root@cosmian.fr" \
      -passin pass:root123

echo "checking ca cert"
openssl x509 -noout -text -in certs/ca.cert.pem

## making Intermediate Environment
echo "Making intermediate environment"
mkdir intermediate/certs intermediate/crl intermediate/csr intermediate/newcerts intermediate/private
touch ./intermediate/index.txt
echo 1000 >intermediate/serial
echo 1000 >intermediate/crlnumber

## Generating Intermediate
echo "Generating intermediate key"
openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem -passout pass:intermediate123 4096

echo "Generating intermediate csr"
openssl req -batch -config openssl_int.cnf -new -sha256 \
      -key intermediate/private/intermediate.key.pem \
      -out intermediate/csr/intermediate.csr.pem \
      -subj "/C=FR/ST=France/L=IDF/O=Cosmian/CN=Intermediate/emailAddress=intermediate@cosmian.fr" \
      -passin pass:intermediate123

echo "Generating intermediate cert"
openssl ca -batch -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in intermediate/csr/intermediate.csr.pem \
      -out intermediate/certs/intermediate.cert.pem -passin pass:root123

echo "Removing password protection from intermediate key"
openssl rsa -in intermediate/private/intermediate.key.pem -out intermediate/private/intermediate.key -passin pass:intermediate123
echo "Generating intermediate pkcs12"

openssl pkcs12 -export -in intermediate/certs/intermediate.cert.pem \
      -inkey intermediate/private/intermediate.key \
      -out intermediate/private/intermediate.p12 \
      -passout pass:secret \
      -certfile certs/ca.cert.pem

echo "Extracting certificate from intermediate.p12"
openssl pkcs12 -in intermediate/private/intermediate.p12 -clcerts -nokeys -out intermediate/certs/intermediate_from_p12.cert.pem -passin pass:secret

echo "printing intermediate cert"
openssl x509 -noout -text \
      -in intermediate/certs/intermediate.cert.pem

echo "verifying intermediate cert"
openssl verify -CAfile certs/ca.cert.pem \
      intermediate/certs/intermediate.cert.pem

echo "Building certificate chain"
cat intermediate/certs/intermediate.cert.pem \
      certs/ca.cert.pem >intermediate/certs/ca-chain.cert.pem

## Leaf1

echo "LEAVES"
openssl genrsa -aes256 \
      -out intermediate/private/leaf1.key.pem -passout pass:leaf1123 2048

openssl req -batch -config openssl_int.cnf \
      -key intermediate/private/leaf1.key.pem \
      -new -sha256 -out intermediate/csr/leaf1.csr.pem \
      -subj "/C=FR/ST=France/L=IDF/O=Cosmian/CN=Leaf1/emailAddress=l1@cosmian.fr" \
      -passin pass:leaf1123

openssl ca -batch -config openssl_int.cnf \
      -extensions server_cert -days 3650 -notext -md sha256 \
      -in intermediate/csr/leaf1.csr.pem \
      -out intermediate/certs/leaf1.cert.pem -passin pass:intermediate123

## Leaf2

openssl genrsa -aes256 \
      -out intermediate/private/leaf2.key.pem -passout pass:leaf2123 2048

openssl req -batch -config openssl_int.cnf \
      -key intermediate/private/leaf2.key.pem \
      -new -sha256 -out intermediate/csr/leaf2.csr.pem \
      -subj "/C=FR/ST=France/L=IDF/O=Cosmian/CN=Leaf2/emailAddress=l2@cosmian.fr" \
      -passin pass:leaf2123

openssl ca -batch -config openssl_int.cnf \
      -extensions server_cert -days 3650 -notext -md sha256 \
      -in intermediate/csr/leaf2.csr.pem \
      -out intermediate/certs/leaf2.cert.pem -passin pass:intermediate123

openssl ca -batch -config openssl_int.cnf \
      -gencrl -out intermediate/crl/intermediate.crl.pem -passin pass:intermediate123

cat intermediate/certs/ca-chain.cert.pem intermediate/crl/intermediate.crl.pem >chain_t0.pem

openssl verify -crl_check -CAfile chain_t0.pem \
      intermediate/certs/leaf1.cert.pem

openssl verify -crl_check -CAfile chain_t0.pem \
      intermediate/certs/leaf2.cert.pem

## Revoking Leaf1
openssl ca -config openssl_int.cnf \
      -revoke intermediate/certs/leaf1.cert.pem -passin pass:intermediate123

## generating CRL for Intermediate
rm intermediate/crl/intermediate.crl.pem
openssl ca -config openssl_int.cnf \
      -gencrl -out intermediate/crl/intermediate.crl.pem -passin pass:intermediate123

cat intermediate/certs/ca-chain.cert.pem intermediate/crl/intermediate.crl.pem >chain_t1.pem

openssl verify -crl_check -CAfile chain_t1.pem \
      intermediate/certs/leaf1.cert.pem || true

openssl verify -crl_check -CAfile chain_t1.pem \
      intermediate/certs/leaf2.cert.pem

cp certs/ca.cert.pem ../../
cp intermediate/certs/intermediate.cert.pem ../../
cp intermediate/certs/leaf1.cert.pem ../../
cp intermediate/certs/leaf2.cert.pem ../../

openssl x509 -outform der -in ../../ca.cert.pem -out ../../ca.cert.der
openssl x509 -outform der -in ../../intermediate.cert.pem -out ../../intermediate.cert.der
openssl x509 -outform der -in ../../leaf1.cert.pem -out ../../leaf1.cert.der
openssl x509 -outform der -in ../../leaf2.cert.pem -out ../../leaf2.cert.der

scp intermediate/crl/intermediate.crl.pem cosmian@package.cosmian.com:/mnt/package/kms/crl_tests

cp certs/ca.cert.pem ../..
cp intermediate/certs/intermediate.cert.pem ../..
cp intermediate/certs/leaf1.cert.pem ../..
cp intermediate/certs/leaf2.cert.pem ../..
cp ../../ca.cert.der ../..
cp ../../intermediate.cert.der ../..
cp ../../leaf1.cert.der ../..
cp ../../leaf2.cert.der ../..
