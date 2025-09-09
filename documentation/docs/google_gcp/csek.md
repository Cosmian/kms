To
use [Customer Supplied Encryption Keys](https://cloud.google.com/docs/security/encryption/customer-supplied-encryption-keys),
follow the general instructions on
using [RSA wrapping keys](https://cloud.google.com/compute/docs/disks/customer-supplied-encryption?hl=en#rsa-encryption).

<!-- TOC -->
  * [Generate a symmetric key in Cosmian KMS](#generate-a-symmetric-key-in-cosmian-kms)
  * [Download the Google CSEK Certificate and extract the RSA wrapping key](#download-the-google-csek-certificate-and-extract-the-rsa-wrapping-key)
  * [Import the RSA wrapping key in Cosmian KMS](#import-the-rsa-wrapping-key-in-cosmian-kms)
  * [Export the wrapped CSEK Symmetric Key](#export-the-wrapped-csek-symmetric-key)
  * [Convert the wrapped CSEK Symmetric Key to base64](#convert-the-wrapped-csek-symmetric-key-to-base64)
<!-- TOC -->

## Generate a symmetric key in Cosmian KMS

This is the symmetric key that will be used as the CSEK.

```shell
cosmian kms sym keys create  --number-of-bits 256 CSEK_Sym_Key

The symmetric key was successfully generated.
          Unique identifier: CSEK_Sym_Key
```

## Download the Google CSEK Certificate and extract the RSA wrapping key

Download the certificate

```shell
curl  https://cloud-certs.storage.googleapis.com/google-cloud-csek-ingress.pem > google-cloud-csek-ingress.pem
```

Extract the (public) RSA wrapping key

```shell
openssl x509 -pubkey -noout -in google-cloud-csek-ingress.pem > rsa_pubkey.pem
```

## Import the RSA wrapping key in Cosmian KMS

```shell
cosmian kms rsa keys import  --key-format pem  --key-usage encrypt --key-usage wrap-key rsa_pubkey.pem CSEK_Wrapping_Key

The PublicKey in file rsa_pubkey.pem was imported with id: CSEK_Wrapping_Key
          Unique identifier: CSEK_Wrapping_Key
```

## Export the wrapped CSEK Symmetric Key

The export performs CKM_RSA_PKCS_OAEP key wrapping with a SHA1 digest.

```shell
 cosmian kms rsa keys export --key-id CSEK_Sym_Key --wrap-key-id CSEK_Wrapping_Key \
 --wrapping-algorithm rsa-oaep-sha1 --key-format raw wrapped_key.bin
 
The key CSEK_Sym_Key of type SymmetricKey was exported to "wrapped_key.bin"
          Unique identifier: CSEK_Sym_Key
```

Note 1: make sure you use `rsa-oaep-sha1` to force the SHA1 digest.
Note 2: the wrapped key should be 2048 bits (256 bytes) long.

## Convert the wrapped CSEK Symmetric Key to base64

```shell
base64 -i wrapped_key.bin 

BtE+r06qy4isyfMR29n5uGSPj1qbOQTA42nxVJ...Hw==
```