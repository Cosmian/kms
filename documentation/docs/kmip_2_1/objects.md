The KMIP 2.1 specification pre-defines a set of 9 cryptographic objects. Cosmian supports the use of 4 of these objects

| Object              | Cosmian KMS                                    |
|---------------------|------------------------------------------------|
| Certificate         | X509                                           |
| Certificate Request | -                                              |
| Opaque Object       | -                                              |
| PGP Key             | -                                              |
| Private Key         | CoverCrypt, X25519, Ed25519 X448, Ed448, NIST  |
| Public Key          | CoverCrypt, X25519, Ed25519, X448, Ed448, NIST |
| Secret Data         | -                                              |
| Split Key           | -                                              |
| Symmetric key       | SSE, AES, FPE, Salsa20, XChacha20, Findex      |

**Notes**:

 - Key paris for NIST curves P-192, P-224, P-256, P-384, P-521 and RSA 2048, 3072, 4096 are supported via the Import/Export API. 
     Creation of these key pairs directly in the KMS should be available soon.
 - Certificates can be 
     - imported using the Import operation as X509 (PEM, DER) or PKCS12 (PFX) files.
     - created using the Certify operation from a PKCS#10 Certificate Request or from an existing public key.
 - For the supported algorithms for key wrapping, encryption and decryption, see the Encrypt and Decrypt
      API documentation.
