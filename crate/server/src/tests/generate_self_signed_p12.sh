#!/bin/bash

cat > "/tmp/openssl.cnf" << EOF
[req]
default_bits = 2048
encrypt_key  = no # Change to encrypt the private key using des3 or similar
default_md   = sha256
prompt       = no
utf8         = yes
# Specify the DN here so we aren't prompted (along with prompt = no above).
distinguished_name = req_distinguished_name
# Extensions for SAN IP and SAN DNS
x509_extensions = x509_extensions

# Be sure to update the subject to match your organization.
[req_distinguished_name]
C  = FR
ST = Ile-De-France
L  = Paris
O  = Cosmian
CN = localhost
# Allow client and server auth. You may want to only allow server auth.
# Link to SAN names.
# keyUsage             = digitalSignature, keyEncipherment
# extendedKeyUsage     = clientAuth, serverAuth

[x509_extensions]
basicConstraints     = critical,CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName       = @alt_names

# Alternative names are specified as IP.# and DNS.# for IP addresses and
# DNS accordingly.
[alt_names]
IP.1  = 127.0.0.1
DNS.1 = my.dns.name
EOF

# Create a self-signed cert
openssl req -x509 -new -config "/tmp/openssl.cnf" -days 365  -keyout /tmp/test.key -out /tmp/test.crt

# openssl x509 -in /tmp/test.crt -out /tmp/test.crt.der -outform DER

# Generate a PKCS12 file
openssl pkcs12 -export -out /tmp/test.p12 -inkey /tmp/test.key -in /tmp/test.crt -password pass:
