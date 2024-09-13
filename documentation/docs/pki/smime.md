Google requirements:
https://support.google.com/a/answer/7300887?fl=1&sjid=2093401421194266294-NA

## Creating a Root CA

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

## Creating an intermediate CA

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

```sh
 ckms certificates certify --certificate-id acme_intermediate_ca \
 --issuer-certificate-id acme_root_ca \
 --generate-key-pair --algorithm nist-p256  \
 --subject-name "CN=ACME S/MIME intermediate,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
 --days 1825 \
 --certificate-extensions intermediate.ext
 ```

## Generate a S/MIME certificate for a user

Let us create a S/MIME certificate for user john.doe@acme.com, signed by the intermediate
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

```text
[ v3_ca ]
keyUsage=digitalSignature,nonRepudiation,keyAgreement
extendedKeyUsage=emailProtection
subjectAltName=email:john.doe@acme.com
crlDistributionPoints=URI:https://acme.com/crl.pem
```

```sh
ckms certificates certify --certificate-id john_doe \
--issuer-certificate-id acme_intermediate_ca \
--generate-key-pair --algorithm nist-p256  \
--subject-name "CN=john.doe@acme.com,OU=IT,O=ACME,L=San Francisco,ST=California,C=US" --days 365 \
--certificate-extensions user.ext
```

## Export and view the certificate in PEM format

To export the certificate in PEM format, use the following command:

```sh
 ckms certificates export --certificate-id john_doe --format pem john_doe.pem
 ```

You can the view its content, using `openssl` for instance:

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

## Export the certificate and the private key in PKCS12 format

To export the certificate and the private key in PKCS12 format,

```sh
 ckms certificates export --certificate-id john_doe \
 --format pkcs12 --pkcs12-password mysecret \
 john_doe.p12
 ```

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