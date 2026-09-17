---
name: 'Rust Crypto (FIPS)'
description: 'FIPS 140-3 cryptographic rules for crate/crypto/'
applyTo: 'crate/crypto/**/*.rs'
---

# Cryptographic primitives rules

## FIPS-approved algorithms (default build)

Only these algorithms are allowed without the `non-fips` feature flag:

- **Symmetric**: AES-128, AES-256 (GCM, CBC, CTR, KW, KWP)
- **Asymmetric**: RSA (2048, 3072, 4096), EC (P-256, P-384, P-521), Ed25519/Ed448 (signing only)
- **Hash**: SHA-256, SHA-384, SHA-512, SHA-3
- **MAC**: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, CMAC-AES
- **KDF**: HKDF, SP 800-108 KBKDF

## Non-FIPS algorithms (require `#[cfg(feature = "non-fips")]`)

- Covercrypt, AES-XTS, ML-KEM, ML-DSA, SLH-DSA, ChaCha20-Poly1305
- Gate at function or module level, never inside function bodies.

## OpenSSL provider initialization

- `apply_openssl_dir_env_if_needed()` **must** be called before any `Provider::try_load()`.
- FIPS provider is loaded once via `OnceLock` in `crate/server/src/openssl_providers.rs`.
- Non-FIPS mode loads the legacy provider on top of the default provider.
- No external OpenSSL dependency — `build.rs` downloads and builds OpenSSL 3.6.2.

## Key size enforcement

- RSA keys below 2048 bits are rejected in FIPS mode.
- EC curves not in {P-256, P-384, P-521} are rejected in FIPS mode.

## Testing crypto changes

```bash
cargo test -p cosmian_kms_crypto              # FIPS mode
cargo test -p cosmian_kms_crypto --features non-fips  # non-FIPS mode
```

> For a full cryptographic compliance audit (FIPS + BSI + ANSSI), run `/cryptography-review`.
