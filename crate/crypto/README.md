# Cosmian KMS Crypto

Cryptographic primitives wrapper around OpenSSL 3.6.0. Implements AES, RSA, EC, SHA-2/3, HMAC, key derivation, and (with `non-fips`) PQC (ML-KEM, ML-DSA, SLH-DSA, Covercrypt), Argon2, ChaCha20-Poly1305.

`build.rs` downloads OpenSSL 3.6.0, verifies SHA-256, and builds it. See `src/openssl_providers.rs` for FIPS/non-FIPS provider initialization.
