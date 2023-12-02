The Cosmian server supports a growing list of cryptographic algorithms.

## Key-wrapping

The Cosmian server supports key-wrapping via the `Import`and `Export` kmip operations. The supported key-wrapping algorithms are:

| Algorithm            | Wrap Key Type               | Description                                                                                                  |
|----------------------|-----------------------------|--------------------------------------------------------------------------------------------------------------|
| RFC 5649             | AES                         | AES key-wrapping with padding as defined in [RFC3394](https://tools.ietf.org/html/rfc5649)                   |
| CKM_RSA_AES_KEY_WRAP | RSA 2048, 3072 or 4096 bits | RSA OAEP with AES-256 GCM and Sha256                                                                         |
| Salsa Sealed Box     | X25519, Ed25519             | ECIES compatible with libsodium [Sealed Box](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) | 
| ECIES NIST AES-128   | P-192, P-224, P-256, P-384  | ECIES with a NIST curve and AES-128 GCM                                                                      |  

- `CKM_RSA_AES_KEY_WRAP` is a PKCS#11 mechanism that is supported by most HSMs. It is compatible with Google KMS
    - RSA_OAEP_3072_SHA256_AES_256 for RSA 3072 bits key
    - RSA_OAEP_4096_SHA256_AES_256 for RSA 4096 bits key
- `Salsa sealed box` uses X25519 and XSalsa20-Poly1305. A Ed25519 wrapping key can be used; it will be converted to X25519 first.
- There is no NIST standard for ECIES; `SalsaSealbox` if fast and widely used.

## Covercrypt

[Covercrypt](https://github.com/Cosmian/cover_crypt) is a new cryptographic alogrithm, being standardized at [ETSI]](https://www.etsi.org/)
that allows creating ciphertexts for a set of attributes and issuing user keys with access policies over these attributes