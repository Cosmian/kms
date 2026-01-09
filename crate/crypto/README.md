// TODO : rewrite some stuff



# Cosmian KMS Crypto

The **Crypto** crate provides core cryptographic operations and algorithm implementations for the Cosmian KMS.

## Overview

This crate implements the cryptographic foundation of the KMS, providing secure implementations of various encryption, decryption, signing, and key management algorithms. It supports both FIPS-compliant and non-FIPS cryptographic operations.

## Features

### FIPS Compliance

The crate supports FIPS 140-3 compliant cryptographic operations when built without the `non-fips` feature. This ensures compliance with federal security standards.

### Non-FIPS Features (enabled with `non-fips` feature)

- **Advanced Encryption**: AES-GCM-SIV encryption
- **Password Hashing**: Argon2 password-based key derivation
- **Post-Quantum Cryptography**: Covercrypt algorithm support
- **Additional Hash Functions**: BLAKE and other hash algorithms
- **Stream Ciphers**: ChaCha20-Poly1305 support

## Supported Algorithms

### Symmetric Encryption

- **AES**: Advanced Encryption Standard (128, 192, 256-bit keys)
- **AES-GCM**: Authenticated encryption with Galois/Counter Mode
- **AES-GCM-SIV**: Synthetic Initialization Vector mode (non-FIPS only)
- **ChaCha20-Poly1305**: Stream cipher with authentication (non-FIPS only)

### Asymmetric Cryptography

- **RSA**: Key generation, encryption, decryption, and digital signatures
- **Elliptic Curve**: ECDSA signatures and ECDH key exchange
- **EdDSA**: Edwards-curve digital signatures

### Hash Functions

- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **BLAKE**: High-speed cryptographic hash function (non-FIPS only)

### Key Derivation

- **PBKDF2**: Password-Based Key Derivation Function 2
- **Argon2**: Memory-hard password hashing (non-FIPS only)
- **HKDF**: HMAC-based Key Derivation Function

### Post-Quantum Cryptography

- **Covercrypt**: Attribute-based encryption (non-FIPS only)

## Key Components

### Algorithm Implementations

- **Symmetric Operations**: Encryption, decryption, and key generation for symmetric algorithms
- **Asymmetric Operations**: Key pair generation, public key operations, and digital signatures
- **Hash Operations**: Secure hash computation and verification
- **Key Management**: Key derivation, wrapping, and unwrapping operations

### OpenSSL Integration

The crate leverages OpenSSL for cryptographic operations, ensuring:

- High performance through optimized implementations
- Hardware acceleration when available
- FIPS compliance when configured appropriately
- Extensive algorithm support

### Error Handling

Comprehensive error handling for:

- Invalid key formats or sizes
- Unsupported algorithm parameters
- Cryptographic operation failures
- FIPS compliance violations

## Usage Examples

This crate is primarily used internally by the KMS server for all cryptographic operations. It provides the cryptographic primitives that power:

- Key generation and management
- Data encryption and decryption
- Digital signature creation and verification
- Certificate operations
- Secure communication protocols

## Dependencies

- **OpenSSL**: Core cryptographic library
- **cosmian_crypto_core**: Cosmian's cryptographic primitives
- **cosmian_kmip**: KMIP protocol types and structures
- **cosmian_cover_crypt**: Post-quantum cryptography (optional)
- **aes-gcm-siv**: Advanced AES mode (optional)
- **argon2**: Password hashing (optional)

## Security Considerations

- All cryptographic operations follow industry best practices
- FIPS mode ensures compliance with federal security standards
- Secure random number generation for all cryptographic operations
- Proper key lifecycle management and secure memory handling

## Building

### FIPS Mode (Default)

```bash
cargo build
```

### Non-FIPS Mode

```bash
cargo build --features non-fips
```

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
