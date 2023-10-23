To generate a certificate authority (CA) that will sign an intermediate certificate with OpenSSL in the command line, you can use the following steps:

## Root CA

**1. Generate a private key for the CA.**

```bash
openssl genrsa -out ca.key 3072
```

This will generate a 2048-bit RSA private key for the CA. The private key will be stored in the file `ca.key`.

**2. Generate a self-signed certificate for the CA.**

```bash
openssl req -new -x509 -key ca.key -out ca.crt -days 3650
```

This will generate a self-signed certificate for the CA that is valid for 365 days. The certificate will be stored in the file `ca.crt`.

**3. Create a PKCS#12 file for the CA.**

```bash
openssl pkcs12 -export -out ca.p12 -inkey ca.key -in ca.crt
```


## Intermediate

Google rules for S/MIME certificates: [here](https://support.google.com/a/answer/7300887?hl=en&ref_topic=9061730&sjid=4609582991418590396-EU#zippy=%2Cend-entity-certificate%2Cintermediate-ca-certificate-that-issues-the-end-entity%2Croot-ca)

- Key Usage: Bit positions must be set for: keyCertSign. and digitalSignature
- Extended Key Usage: Must be present: emailProtection
- Basic Constraints: cA field must be set true; pathLenConstraint field SHOULD be present and SHOULD be 0
- CRL Distribution Points: At least one publicly accessible HTTP uniformResourceIdentifier must be present.




**1. Generate a private key for the intermediate certificate.**

```bash
openssl genrsa -out intermediate.key 3072
```

This will generate a 2048-bit RSA private key for the intermediate certificate. The private key will be stored in the file `intermediate.key`.

**2. Generate a certificate signing request (CSR) for the intermediate certificate.**

``` bash
openssl req -new -key intermediate.key -out intermediate.csr
```

This will generate a CSR for the intermediate certificate. The CSR will be stored in the file `intermediate.csr`.

**3. Sign the CSR with the CA's private key.**

To set the Key Usage and Extended Key Usage extensions and the CRL Distribution Point extension in the intermediate certificate, you can use the following options:

```bash
openssl x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key -out intermediate.crt -days 1825 -extensions v3_ca -extfile intermediate.ext -CRLurl https://csr.example.com/crl.pem
```

The `intermediate.ext` file should contain the following text:

```
[ v3_ca ]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:http://cse.example.com/crl.pem
```

The `crlDistributionPoints` option should be replaced with the URL of a publicly accessible HTTP uniformResourceIdentifier that contains the CRL for the intermediate certificate.

This will sign the CSR with the CA's private key and generate an intermediate certificate. The intermediate certificate will be stored in the file `intermediate.crt`.


**4. Create a PKCS#12 file for the intermediate certificate.**

```bash
openssl pkcs12 -export -out intermediate.p12 -inkey intermediate.key -in intermediate.crt
```

This will create a PKCS#12 file for the intermediate certificate. The PKCS#12 file will contain the intermediate certificate's private key and certificate.
