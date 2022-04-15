

The KMIP 2.1 specification pre-defines a set of 9 cryptographic objects. Cosmian support its cryptographic library needs though the use of 4 of these objects


| Object              | Cosmian KMS                           |
| ------------------- | --------------------------------------|
| Certificate         | -                                     |
| Certificate Request | -                                     |
| Opaque Object       | -                                     |
| PGP Key             | -                                     |
| Private Key         | ABE, X25519                           |
| Public Key          | ABE, X25519                           |
| Secret Data         | DMCFE                                 |
| Split Key           | -                                     |
| Symmetric key       | SSE, AES, TFHE, DMCFE, FPE, xChacha20 |


The DMCE Functional Key does not exist as a separate object in the KMIP standard is mapped to a Secret Data Object.

The LWE keys used with DMCE and TFHE are actually symmetric keys, they both encrypt and decrypt, although there exists a sort of "Public Key" which is an Encryption of the value zero. Being a probabilistic Cipher Text, this "Publik Key" is not mapped to any KMP object.

