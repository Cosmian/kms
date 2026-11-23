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
- Put `#[cfg(feature = "non-fips")]` on a function, module, `impl`, struct field, enum variant or match arm. Never wrap statements or blocks inside a function body (`#[cfg(..)] { .. }`, `#[cfg(..)] let ..`, paired `#[cfg(feature..)]`/`#[cfg(not(feature..))]` statements) and never branch on `cfg!(feature = "non-fips")` at runtime: split into two functions with opposite `#[cfg]` and call the right one. About 30 existing files violate this (e.g. `create_key_pair.rs`, `export_get.rs`, `decrypt.rs`): legacy — when you touch one, fix it in the same change.

## OpenSSL provider initialization

- Provider loading goes exclusively through `init_openssl_providers()` in `crate/server/src/openssl_providers.rs` (`OnceLock`); never call `Provider::load` or `Provider::try_load` elsewhere.
- FIPS mode loads the `fips` provider; non-FIPS mode loads the `legacy` provider on top of the active `default` provider.
- No external OpenSSL dependency — `crate/crypto/build.rs` downloads and builds OpenSSL 3.6.5 (main library) plus OpenSSL 3.1.2 (CMVP-validated FIPS module `fips.so` in FIPS builds), and emits `OPENSSL_CONF` and `OPENSSL_MODULES` at compile time via `cargo:rustc-env`.

## Key size enforcement

- RSA keys below 2048 bits are rejected in FIPS mode.
- EC curves not in {P-256, P-384, P-521} are rejected in FIPS mode.

## Testing crypto changes

```bash
cargo test -p cosmian_kms_crypto              # FIPS mode
cargo test -p cosmian_kms_crypto --features non-fips  # non-FIPS mode
```

> Run `/cryptography-review` for changes in this crate and for algorithm selection, key lifecycle/policy, provider initialization, or FIPS gates elsewhere. Do not use a clean mechanical audit as a crypto-review skip condition.
