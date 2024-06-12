#To generate a certificate authority (CA) that will sign an intermediate certificate with OpenSSL in the command line, you can use the following steps:

# Clean-up
rm ca.*
rm intermediate.*
rm leaf.*
rm blue* red*
rm *fullchain.*

set -e

## Root CA

#-1. Generate a private key for the CA.**
# This will generate a 4096-bit RSA private key for the CA. The private key will be stored in the file `ca.key`.
openssl genrsa -out ca.key 4096

#-2. Generate a self-signed certificate for the CA.**
# This will generate a self-signed certificate for the CA that is valid for 365 days. The certificate will be stored in the file `ca.pem`.
openssl req -new -x509 -key ca.key -out ca.pem -days 3650 -subj "/C=FR/ST=IdF/L=Paris/O=Cosmian/OU=R&D/CN=cosmian.com Root"

#-3. Create a PKCS#12 file for the CA.**
openssl pkcs12 -export -out ca.p12 -inkey ca.key -in ca.pem -passout pass:secret

## Intermediate

# Google rules for S/MIME certificates: [here](https://support.google.com/a/answer/7300887?hl=en&ref_topic=9061730&sjid=4609582991418590396-EU#zippy=%2Cend-entity-certificate%2Cintermediate-ca-certificate-that-issues-the-end-entity%2Croot-ca)
#
# - Key Usage: Bit positions must be set for: keyCertSign. and digitalSignature
# - Extended Key Usage: Must be present: emailProtection
# - Basic Constraints: cA field must be set true; pathLenConstraint field SHOULD be present and SHOULD be 0
# - CRL Distribution Points: At least one publicly accessible HTTP uniformResourceIdentifier must be present.

#-1. Generate a private key for the intermediate certificate.**
# This will generate a 4096-bit RSA private key for the intermediate certificate. The private key will be stored in the file `intermediate.key`.
openssl genrsa -out intermediate.key 4096

#-2. Generate a certificate signing request (CSR) for the intermediate certificate.**
# This will generate a CSR for the intermediate certificate. The CSR will be stored in the file `intermediate.csr`.
openssl req -new -key intermediate.key -out intermediate.csr -subj "/C=FR/ST=IdF/L=Paris/O=Cosmian/OU=R&D/CN=cosmian.com Intermediate"

#-3. Sign the CSR with the CA's private key.**
# To set the Key Usage and Extended Key Usage extensions and the CRL Distribution Point extension in the intermediate certificate, you can use the following options:
# The `intermediate.ext` file should contain the following text:
#
# ```
# [ v3_ca ]
# basicConstraints=CA:TRUE,pathlen:0
# keyUsage=keyCertSign,digitalSignature
# extendedKeyUsage=emailProtection
# crlDistributionPoints=URI:http://cse.example.com/crl.pem
# ```
# The `crlDistributionPoints` option should be replaced with the URL of a publicly accessible HTTP uniformResourceIdentifier that contains the CRL for the intermediate certificate.
# This will sign the CSR with the CA's private key and generate an intermediate certificate. The intermediate certificate will be stored in the file `intermediate.pem`.
openssl x509 -req -in intermediate.csr -CA ca.pem -CAkey ca.key -out intermediate.pem -days 3650 -extensions v3_ca -extfile extensions.ext

#-4. Create a PKCS#12 file for the intermediate certificate.**
# This will create a PKCS#12 file for the intermediate certificate. The PKCS#12 file will contain the intermediate certificate's private key and certificate.
openssl pkcs12 -export -out intermediate.p12 -inkey intermediate.key -in intermediate.pem -passout pass:secret

## Leaf certificate

#-1. Generate a private key for the leaf certificate.**
# This will generate a 4096-bit RSA private key for the leaf certificate. The private key will be stored in the file `leaf.key`.
openssl genrsa -out leaf.key 4096

#-2 Generate a certificate signing request (CSR) for the leaf certificate.**
# This will generate a CSR for the leaf certificate. The CSR will be stored in the file `leaf.csr`.
openssl req -new -key leaf.key -out leaf.csr -subj "/C=FR/ST=IdF/L=Paris/O=Cosmian/OU=R&D/CN=Test Leaf"

#-3. Sign the CSR with the Intermediate's private key.**
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key -out leaf.pem -days 3650 -extensions v3_req -extfile extensions_leaf.ext

# Build fullchain certificate
cp leaf.pem fullchain.pem
cat intermediate.pem >> fullchain.pem
cat ca.pem >>fullchain.pem

# reversed chain
cp ca.pem reversed_fullchain.pem
cat intermediate.pem >>reversed_fullchain.pem
cat leaf.pem >>reversed_fullchain.pem

leaf() {
  user="$1"
  ## Leaf certificate

  #-1. Generate a private key for the leaf certificate.**
  # This will generate a 4096-bit RSA private key for the leaf certificate. The private key will be stored in the file `leaf.key`.
  openssl genrsa -out ${user}.key 4096

  #-2 Generate a certificate signing request (CSR) for the leaf certificate.**
  # This will generate a CSR for the leaf certificate. The CSR will be stored in the file `leaf.csr`.
  openssl req -new -key ${user}.key -out ${user}.csr -subj "/C=FR/ST=IdF/L=Paris/O=Cosmian/OU=R&D/CN=${user}@cosmian.com/emailAddress=${user}@cosmian.com"

  #-3. Sign the CSR with the Intermediate's private key.**
  openssl x509 -req -in ${user}.csr -CA intermediate.pem -CAkey intermediate.key -out ${user}.pem -days 3650 -extensions v3_req -extfile extensions_leaf.ext
  openssl crl2pkcs7 -nocrl -certfile ${user}.pem -out ${user}@cosmian.com.p7pem -certfile intermediate.pem -certfile ca.pem
  # openssl pkcs7 -inform DER -in {old_name.p7b} -outform PEM -out {new_name.p7pem}

  openssl verify -CAfile ca.pem -untrusted intermediate.pem ${user}.pem
  openssl verify -CAfile fullchain.pem ${user}.pem
}

leaf red
leaf blue
leaf green
