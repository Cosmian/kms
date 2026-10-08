# Supported Objects

The KMIP 2.1 specification pre-defines a set of 9 cryptographic objects. Eviden supports the following objects:

| Objects             | Cryptographic primitives                               |
|---------------------|--------------------------------------------------------|
| Certificate         | X509                                                   |
| Certificate Request | -                                                      |
| Opaque Object       | -                                                      |
| PGP Key             | RSA, Ed25519 (non-FIPS)                                |
| Private Key         | Covercrypt, X25519, Ed25519, X448, Ed448, NIST EC, RSA |
| Public Key          | Covercrypt, X25519, Ed25519, X448, Ed448, NIST EC, RSA |
| Secret Data         | -                                                      |
| Split Key           | -                                                      |
| Symmetric key       | SSE, AES, FPE, Salsa20, XChacha20, Findex              |

**Notes**:

- Certificates can be
    - imported using the `Import` operation as X509 (PEM, DER) or PKCS12 (PFX) files.
    - created using the `Certify` operation from a PKCS#10 Certificate Request or from an existing public key.
- PGP Keys can be created (RFC 9580 v4 secret key), imported, exported (secret or public armor), and used for KMIP `Encrypt`, `Decrypt`, `Sign`, and `SignatureVerify` in non-FIPS mode.
- For the supported algorithms for key wrapping, encryption and decryption, see the [supported algorithms](../certifications_and_compliance/cryptographic_algorithms/algorithms.md) page.
- For the supported formats, see the [supported formats](./formats.md) page.
