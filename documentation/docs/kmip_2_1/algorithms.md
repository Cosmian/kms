The Cosmian server supports a growing list of cryptographic algorithms.

## Key-wrapping

The Cosmian server supports key-wrapping via the `Import`(unwrapping) and `Export` (wrapping) kmip operations.
The (un)wrapping key identifier may be that of a key or a certificate.
In the latter case, the public key (or the associated private key for unwrapping, if any) will be retrieved and used.

The supported key-wrapping algorithms are:

| Algorithm            | Wrap Key Type               | Description                                                                                                                                                                 |
|----------------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RFC 5649             | AES                         | AES key-wrapping with padding as defined in [RFC3394](https://tools.ietf.org/html/rfc5649)                                                                                  |
| CKM_RSA_AES_KEY_WRAP | RSA 2048, 3072 or 4096 bits | RSA OAEP with AES-256 GCM and Sha256 as defined in [RSA AES KEY WRAP](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908) |
| Salsa Sealed Box     | X25519, Ed25519             | ECIES compatible with libsodium [Sealed Box](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)                                                                |
| ECIES NIST AES-128   | P-192, P-224, P-256, P-384  | ECIES with a NIST curve and AES-128 GCM                                                                                                                                     |

- `CKM_RSA_AES_KEY_WRAP` is a PKCS#11 mechanism that is supported by most HSMs. It is compatible with Google KMS
  - RSA_OAEP_3072_SHA256_AES_256 for RSA 3072 bits key
  - RSA_OAEP_4096_SHA256_AES_256 for RSA 4096 bits key
- `Salsa sealed box` uses X25519 and XSalsa20-Poly1305. A Ed25519 wrapping key can be used; it will be converted to
  X25519 first.
- There is no NIST standard for ECIES; `SalsaSealbox` if fast and widely used.

## Encryption schemes

Encryption is supported via the `Encrypt` and `Decrypt` kmip operations.
For bulk operations (i.e. encrypting/decrypting multiple data with the same key),
please refer to [KMIP Messages](./messages.md) that allow combining multiple operations in a single request.

Encryption can be performed using a key or a certificate. Decryption can be performed using a key.

| Algorithm            | Encryption Key Type         | Description                                                                                                                                                                 |
|----------------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Covercrypt           | Covercrypt                  | A fast post-quantum attribute based scheme: [Covercrypt](https://github.com/Cosmian/cover_crypt)                                                                            |
| AES GCM              | AES (128 or 256 bits)       | The NIST standardized symmetric encryption in [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)                                                     |
| CKM_RSA_AES_KEY_WRAP | RSA 2048, 3072 or 4096 bits | RSA OAEP with AES-256 GCM and Sha256 as defined in [RSA AES KEY WRAP](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908) |
| Salsa Sealed Box     | X25519, Ed25519             | ECIES compatible with libsodium [Sealed Box](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)                                                                |
| ECIES NIST AES-128   | P-192, P-224, P-256, P-384  | ECIES with a NIST curve and AES-128 GCM                                                                                                                                     |

- [Covercrypt](https://github.com/Cosmian/cover_crypt) is a new post-quantum cryptographic algorithm, being standardized
  at [ETSI](https://www.etsi.org/) that allows creating ciphertexts for a set of attributes and issuing user keys with access policies over these
  attributes. User keys are traceable with a unique fingerprint.
- AES is used in Galois Counter Mode ([GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)) with a 96 bits nonce and a 128 bits tag.

## Signature

Signature is only supported via the `Certify` operation, which is used to create a certificate either by signing a certificate request,
or building it from an existing public key.

| Algorithm | Signature Key Type         | Description                                                                  |
|-----------|----------------------------|------------------------------------------------------------------------------|
| EcDSA     | P-192, P-224, P-256, P-384 | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |
| EdDSA     | Ed25519                    | See [FIPS-186.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |
