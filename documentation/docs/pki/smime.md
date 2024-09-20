# Deploying email encryption with S/MIME

S/MIME is a [standard](https://en.wikipedia.org/wiki/S/MIME) for public key encryption and signing
of MIME data.
It is used to secure email messages and is supported by most email clients and servers.

- [Deploying email encryption with S/MIME](#deploying-email-encryption-with-smime)
  - [Overview of the S/MIME workflow](#overview-of-the-smime-workflow)
    - [Setup (once)](#setup-once)
    - [Handshake (once per recipient)](#handshake-once-per-recipient)
  - [Generating a key pair and a certificate](#generating-a-key-pair-and-a-certificate)
    - [Getting a user certificate from a public certificate authority](#getting-a-user-certificate-from-a-public-certificate-authority)
    - [Getting an intermediate signer certificate from a public certificate authority](#getting-an-intermediate-signer-certificate-from-a-public-certificate-authority)
    - [Creating an S/MIME certificate authority with a root and intermediate CA](#creating-an-smime-certificate-authority-with-a-root-and-intermediate-ca)
      - [Create a Root CA](#create-a-root-ca)
      - [Create an Intermediate CA](#create-an-intermediate-ca)
    - [Generate a user certificate signed by the intermediate certificate](#generate-a-user-certificate-signed-by-the-intermediate-certificate)
  - [Exporting and viewing](#exporting-and-viewing)
    - [PKCS#12 format](#pkcs12-format)
    - [PEM format](#pem-format)
  - [Loading the PKCS#12 file in an email client](#loading-the-pkcs12-file-in-an-email-client)
  - [Apple mail, MacOS](#apple-mail-macos)
  - [Outlook, Windows](#outlook-windows)
    - [Setup](#setup)
    - [Sending a message](#sending-a-message)

## Overview of the S/MIME workflow

To enable S/MIME, a user will go through the following steps:

### Setup (once)

- Generate a key pair and a certificate holding the correct x509 extensions for S/MIME
- Import this certificate and private key (usually in the form of a PKCS#12 file) in its email
  client

### Handshake (once per recipient)

- Send a signed, non-encrypted, email to a recipient to share its certificate
- Receive a signed, encrypted, or non-encrypted, email from the recipient and import its certificate

No further actions are required to exchange signed encrypted emails with this recipient.

## Generating a key pair and a certificate

For interoperability, the user certificate should be ultimately signed by a public certificate
authority commonly found on email clients. If you want to use your own certificate authority,
for internal use or test purposes, please see the instructions below on how to [create a root CA and
an intermediate CA](#creating-an-smime-certificate-authority-with-a-root-and-intermediate-ca).

Please note that these certificates require certain x509 extensions to be compatible with Google
CSE S/MIME and some other operators. Check the
[Google requirements](https://support.google.com/a/answer/7300887?fl=1&sjid=2093401421194266294-NA)
for details.

For a user, there are 3 main possibilities to generate a key pair and an S/MIME certificate:

### Getting a user certificate from a public certificate authority

Many public authorities can issue user S/MIME certificates. Some authorities even provide free
certificates for personal use. This is the case of
[Actalis](https://www.actalis.com/s-mime-certificates)
for instance.

**Important** some email clients, such as Outlook, consider the email address to be case-sensitive.
Make sure the email address in your request matches the email address you are using
in your email client.

Once generated, these authorities will provide you with a PKCS#12 file containing the certificate
and the private key. The file is usually protected by a password.

This file can directly be imported in your email client.

If you wish to store it in the KMS, you can import it using the following command:

```sh
ckms certificates import --format pkcs12 --pkcs12-password mysecret \
  --replace john_doe.p12 john.doe@acme.com
```

To export it as a PEM file, use the following command:

```sh
ckms certificates export  --format pem --certificate-id john.doe@acme.com john_doe.pem
```

### Getting an intermediate signer certificate from a public certificate authority

If you have many users, you will probably want top buy an intermediate certificate from a public
certificate authority. This intermediate certificate will be used to sign the user certificates.

First, import the intermediate certificate and its private key in the KMS:

```sh
ckms certificates import --format pkcs12 --pkcs12-password mysecret \
  --replace intermediate.p12 acme_intermediate_ca
```

Then [generate a user certificate signed by the intermediate certificate](#generate-a-user-certificate-signed-by-the-intermediate-certificate).

### Creating an S/MIME certificate authority with a root and intermediate CA

If you wish to be your own certificate authority, you can create a root and an intermediate CA.

#### Create a Root CA

Say, we are ACME Inc.
Let us create a self-signed root certificate with the following details:

- Common Name: ACME Root CA
- Organization: ACME
- Organizational Unit: IT
- Locality: New York
- State: New York
- Country: US
- Validity: 10 years (3650 days)
- Key Algorithm: NIST P-256

```sh
ckms certificates certify --certificate-id acme_root_ca \
--generate-key-pair --algorithm nist-p256  \
--subject-name "CN=ACME Root CA,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
--days 3650
```

#### Create an Intermediate CA

Let us create an intermediate CA signed by the Root CA. This intermediate will be used to issue
end-users S/MIME certificates. It will be created with the following details:

- Common Name: ACME Intermediate CA
- Organization: ACME
- Organizational Unit: IT
- Locality: New York
- State: New York
- Country: US
- Validity: 5 years (1825 days)
- Key Algorithm: NIST P-256
- Extensions: a `intermediate.ext` file with the following content:

```text
[ v3_ca ]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:https://acme.com/crl.pem
```

Note: these extensions make the intermediate CA compatible with Google CSE for GMail
[S/MIME requirements](https://support.google.com/a/answer/7300887?fl=1&sjid=2093401421194266294-NA)

```shell
ckms certificates certify --certificate-id acme_intermediate_ca \
 --issuer-certificate-id acme_root_ca \
 --generate-key-pair --algorithm nist-p256  \
 --subject-name "CN=ACME S/MIME intermediate,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
 --days 1825 \
 --certificate-extensions intermediate.ext
```

### Generate a user certificate signed by the intermediate certificate

Then, generate a user certificate signed by the intermediate certificate:

**Important** some email clients, such as Outlook, consider the email address to be case-sensitive.
Make sure the email address in the certificate Common Name matches the email address you are using
in your email client.

To be used for S/MIME, the user certificate needs to have certain extensions which are set in a
file containing a `[ v3_ca ]` section.

Say we want to create an S/MIME certificate for user john.doe@acme.com, signed by the intermediate
certificate, with the following details:

- Common Name: john.doe@acme.com
- Organization: ACME
- Organizational Unit: IT
- Locality: San Francisco
- State: California
- Country: US
- Validity: 1 year (365 days)
- Key Algorithm: NIST P-256
- Extensions: a user.ext file with the following content:

The `user.ext` file should contain the following content (which should meet Google CSE
requirements):

```text
[ v3_ca ]
keyUsage=digitalSignature,nonRepudiation,keyAgreement
extendedKeyUsage=emailProtection
subjectAltName=email:john.doe@acme.com
crlDistributionPoints=URI:https://acme.com/crl.pem
```

Issue the following command to generate the certificate:

```sh
ckms certificates certify --certificate-id john.doe@acme.com \
--issuer-certificate-id acme_intermediate_ca \
--generate-key-pair --algorithm nist-p256  \
--subject-name "CN=john.doe@acme.com,OU=IT,O=ACME,L=San Francisco,ST=California,C=US" --days 365 \
--certificate-extensions user.ext
```

## Exporting and viewing

Use the `ckms certificates export` command to export the certificate and the private key in the
desired format. Most email clients require the certificate and the private key to be in a PKCS#12
file.

### PKCS#12 format

To export the certificate and the private key in PKCS#12 format,
use either the `pkcs12` or `pkcs12-legacy` format option.
The `pkcs12-legacy` format is deprecated but is compatible with older versions of OpenSSL (1.1.x)
and some keystores such as the Java keystore or the macOS keychain.

```sh
ckms certificates export --certificate-id john.doe@acme.com \
 --format pkcs12-legacy --pkcs12-password mysecret \
 john_doe.p12
```

OpenSSL can be used to view the content of the PKCS#12 file.
You will need to provide the password you used to protect the file (`mysecret` above).

If you are using OpenSSL 3.0 and above and want to view a legacy PKCS#12 file,
add the `-legacy` option:

```shell
> openssl pkcs12 -info -in john_doe.p12 -nodes

Enter Import Password:
MAC Iteration 2048
MAC verified OK
PKCS7 Encrypted data: Certificate bag
Bag Attributes
    localKeyID: 82 C3 F3 83 32 68 ED B4 71 15 96 12 0B 01 4C 34 8D 58 DC 58
subject=/CN=john.doe@acme.com/OU=IT/C=US/ST=California/L=San Francisco/O=ACME
issuer=/CN=ACME S/MIME intermediate/OU=IT/C=US/ST=New York/L=New York/O=ACME
-----BEGIN CERTIFICATE-----
MIICQDCCAeagAwIBAgIBADAKBggqhkjOPQQDAjByMSEwHwYDVQQDDBhBQ01FIFMv
TUlNRSBpbnRlcm1lZGlhdGUxCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzERMA8G
A1UECAwITmV3IFlvcmsxETAPBgNVBAcMCE5ldyBZb3JrMQ0wCwYDVQQKDARBQ01F
MB4XDTI0MDkxMzA5MzkwMloXDTI1MDkxMzA5MzkwMlowcjEaMBgGA1UEAwwRam9o
bi5kb2VAYWNtZS5jb20xCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
QUNNRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOvAZj+RBjElLMWVipGx+rbG
mniD8NApM2inWLN+1avvd2QslOh9mhiT18u2KJkrjG9hIbVh8cyr4/dxtWL6Goij
bTBrMAsGA1UdDwQEAwIDyDATBgNVHSUEDDAKBggrBgEFBQcDBDAcBgNVHREEFTAT
gRFqb2huLmRvZUBhY21lLmNvbTApBgNVHR8EIjAgMB6gHKAahhhodHRwczovL2Fj
bWUuY29tL2NybC5wZW0wCgYIKoZIzj0EAwIDSAAwRQIgYUf5lGAU3dQ9wIPdX5x+
RtJioGwdVZZmprEAdNL203wCIQDbDk9yRjfPUUWph05LlC45EA8B3OJYEShdo3s9
pImIww==
-----END CERTIFICATE-----
Certificate bag
Bag Attributes: <No Attributes>
subject=/CN=ACME S/MIME intermediate/OU=IT/C=US/ST=New York/L=New York/O=ACME
issuer=/CN=ACME Root CA/OU=IT/C=US/ST=New York/L=New York/O=ACME
-----BEGIN CERTIFICATE-----
MIICJjCCAc2gAwIBAgIBADAKBggqhkjOPQQDAjBmMRUwEwYDVQQDDAxBQ01FIFJv
b3QgQ0ExCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlv
cmsxETAPBgNVBAcMCE5ldyBZb3JrMQ0wCwYDVQQKDARBQ01FMB4XDTI0MDkxMzA5
MzYwNVoXDTI5MDkxMjA5MzYwNVowcjEhMB8GA1UEAwwYQUNNRSBTL01JTUUgaW50
ZXJtZWRpYXRlMQswCQYDVQQLDAJJVDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMREwDwYDVQQHDAhOZXcgWW9yazENMAsGA1UECgwEQUNNRTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABEG7Ei75r1WuGrfMdXEQseoxf4n5KM7Bov5GIP+0
ZSHt2CYEgIkvBElHiLtDs2XP8vPmHKQPA2fOTIqsxGG7NPijYDBeMA8GA1UdEwQI
MAYBAf8CAQAwCwYDVR0PBAQDAgKEMBMGA1UdJQQMMAoGCCsGAQUFBwMEMCkGA1Ud
HwQiMCAwHqAcoBqGGGh0dHBzOi8vYWNtZS5jb20vY3JsLnBlbTAKBggqhkjOPQQD
AgNHADBEAiBbVpxNtT+wLNxAUIrA9r9fR4UT1aCw15rShZZiCjrvcAIgURwRsODz
bB/+NeaLa9WgwjtZk7Vm1c7fVnb30TBcN78=
-----END CERTIFICATE-----
Certificate bag
Bag Attributes: <No Attributes>
subject=/CN=ACME Root CA/OU=IT/C=US/ST=New York/L=New York/O=ACME
issuer=/CN=ACME Root CA/OU=IT/C=US/ST=New York/L=New York/O=ACME
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIBADAKBggqhkjOPQQDAjBmMRUwEwYDVQQDDAxBQ01FIFJv
b3QgQ0ExCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlv
cmsxETAPBgNVBAcMCE5ldyBZb3JrMQ0wCwYDVQQKDARBQ01FMB4XDTI0MDkxMzA5
MzQxNFoXDTM0MDkxMTA5MzQxNFowZjEVMBMGA1UEAwwMQUNNRSBSb290IENBMQsw
CQYDVQQLDAJJVDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYD
VQQHDAhOZXcgWW9yazENMAsGA1UECgwEQUNNRTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABPj86uAwMjnITXnnnLY9wmHbxtGz2IWAN7JLdbmD77RfbpvcK+BxMzVI
20ITcWv8dyfhcMLyBa+ygDVPgVK1jLQwCgYIKoZIzj0EAwIDSQAwRgIhAJenykHa
jjVPke8vX+GyaMTqNJZN94QyCYHgqUeDeZVCAiEAuokqc/TfyzvkzmWcJgeGsFyM
Nk/pqUsPr8eR1sHQWgg=
-----END CERTIFICATE-----
PKCS7 Data
Shrouded Keybag: Bag Attributes
    localKeyID: 82 C3 F3 83 32 68 ED B4 71 15 96 12 0B 01 4C 34 8D 58 DC 58
Key Attributes: <No Attributes>
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQge5si3Le85K18XOLc
ae8QE50qCE0yUMipcPvHwZM1k1ChRANCAATrwGY/kQYxJSzFlYqRsfq2xpp4g/DQ
KTNop1izftWr73dkLJTofZoYk9fLtiiZK4xvYSG1YfHMq+P3cbVi+hqI
-----END PRIVATE KEY-----

```

### PEM format

To export the certificate only, in PEM format, use the following command:

```sh
ckms certificates export --certificate-id john.doe@acme.com --format pem john_doe.pem
```

You can then view its content, using `openssl` for instance:

```shell
> openssl x509 -inform pem -text -in john_doe.pem

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=ACME S/MIME intermediate, OU=IT, C=US, ST=New York, L=New York, O=ACME
        Validity
            Not Before: Sep 11 14:09:25 2024 GMT
            Not After : Sep 11 14:09:25 2025 GMT
        Subject: CN=john.doe@acme.com, OU=IT, C=US, ST=California, L=San Francisco, O=ACME
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4b:0e:f2:7b:5b:93:91:1c:4a:a2:d1:91:24:ce:
                    a4:6e:97:5c:41:9f:fd:92:74:70:83:05:64:69:58:
                    41:46:c5:64:bc:5e:89:30:d6:83:c8:06:64:f6:e8:
                    b9:a2:a9:2f:ad:e5:93:fd:49:45:4c:e5:c3:2b:29:
                    e1:7e:a0:16:a9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage:
                Digital Signature, Non Repudiation, Key Agreement
            X509v3 Extended Key Usage:
                E-mail Protection
            X509v3 Subject Alternative Name:
                <EMPTY>

            X509v3 CRL Distribution Points:

                Full Name:
                  URI:https://acme.com/crl.pem

    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:cf:31:c9:f1:a7:d7:f5:cd:3a:b6:e3:4e:13:
         20:ef:e1:6d:b9:21:55:66:27:c4:5d:b0:68:29:f2:07:7e:5b:
         eb:02:20:1d:92:ff:52:1d:c2:f1:ab:34:f7:d7:f1:29:87:bc:
         f5:33:3c:0b:6c:93:23:4c:4f:c7:69:c1:df:23:95:0e:78
-----BEGIN CERTIFICATE-----
MIICLTCCAdOgAwIBAgIBADAKBggqhkjOPQQDAjByMSEwHwYDVQQDDBhBQ01FIFMv
TUlNRSBpbnRlcm1lZGlhdGUxCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzERMA8G
A1UECAwITmV3IFlvcmsxETAPBgNVBAcMCE5ldyBZb3JrMQ0wCwYDVQQKDARBQ01F
MB4XDTI0MDkxMTE0MDkyNVoXDTI1MDkxMTE0MDkyNVowcjEaMBgGA1UEAwwRam9o
bi5kb2VAYWNtZS5jb20xCzAJBgNVBAsMAklUMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
QUNNRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEsO8ntbk5EcSqLRkSTOpG6X
XEGf/ZJ0cIMFZGlYQUbFZLxeiTDWg8gGZPbouaKpL63lk/1JRUzlwysp4X6gFqmj
WjBYMAsGA1UdDwQEAwIDyDATBgNVHSUEDDAKBggrBgEFBQcDBDAJBgNVHREEAjAA
MCkGA1UdHwQiMCAwHqAcoBqGGGh0dHBzOi8vYWNtZS5jb20vY3JsLnBlbTAKBggq
hkjOPQQDAgNIADBFAiEAzzHJ8afX9c06tuNOEyDv4W25IVVmJ8RdsGgp8gd+W+sC
IB2S/1IdwvGrNPfX8SmHvPUzPAtskyNMT8dpwd8jlQ54
-----END CERTIFICATE-----

```

## Loading the PKCS#12 file in an email client

## Apple mail, MacOS

To use your S/MIME certificate, load it in the login keychain:

![keychain](./images/macos-keychain.png)

Then, in the Mail application, create a new email and tick the "encrypt" and "sign" boxes:

![mail](./images/mail-app-encrypt-sign.png)

When handshaking with a new recipient, send a signed email to the recipient (not encrypted).

When receiving a signed email from the recipient, import the recipient's certificate in
your contacts.

## Outlook, Windows

### Setup

In Outlook (classic) go to File -> Options -> Trust Center -> Trust Center Settings
![outlook_0](./images/outlook_trust_center.png)

Then go to Email Security and click on Import/Export to import the PKCS#12 file.

![outlook_1](./images/outlook_trust_center_1.png)

Finally, go to the Email Security and click the Settings... button of Default Setting.
In the popup, select the certificate you just imported, adjust the hash algorithm to SHA256 for
maximum compatibility and make sure you tick the box "Send these certificates with signed messages."

![outlook_2](./images/outlook_trust_center_2.png)

### Sending a message

Click on New Email, then Options -> Encrypt and Sign.

To perform a handshake with a new recipient, send a first email to the recipient that is signed
only (not encrypted).

![outlook_3](./images/outlook_trust_center_3.png)
