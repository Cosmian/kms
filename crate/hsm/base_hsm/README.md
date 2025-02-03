# Base HSM Implementation

This crate contains the implementation of a PKCS#11 client for a Hardware Security Modules (HSMs).

It provides a set of traits that define the operations that an HSM must support,
as well as a set of data structures that represent the keys and metadata that an HSM can manage.

## Implemented Operations

- Key Generation: Create symmetric (AES) and asymmetric (RSA) keys
- Key Pair Generation: Create public/private key pairs
- Key Export: Export HSM objects
- Key Deletion: Remove keys from the HSM
- Key Search: Find keys based on object type filters
- Encryption/Decryption: Perform cryptographic operations
- Key Information: Retrieve key types and metadata

## Supported Algorithms

- AES: 128-bit and 256-bit keys
- RSA: 1024-bit, 2048-bit, 3072-bit, and 4096-bit keys
