---
name: fips-audit
description: 'Review Rust crypto code for FIPS 140-3 compliance: approved algorithms, key sizes, non-fips gating discipline, and OpenSSL provider init. Use when touching crate/crypto/ or algorithm selection.'
---

# FIPS 140-3 Compliance Audit

Review Rust cryptographic code in this repository for FIPS 140-3 compliance. Covers NIST-approved algorithm enforcement, feature flag gating consistency, key size minimums, and OpenSSL provider initialization.

## When to Use

- Before merging any change to `crate/crypto/src/` or `crate/server/src/core/operations/`
- When adding a new algorithm or key type
- When modifying `#[cfg(feature = "non-fips")]` boundaries
- When changing `crate/server/src/openssl_providers.rs`

## Scope Resolution

If a path was provided, scan only that scope. Otherwise scan:

1. `crate/crypto/src/` — cryptographic primitives
2. `crate/server/src/core/operations/` — per-operation crypto usage
3. `crate/server/src/openssl_providers.rs` — provider init
4. `crate/kmip/src/` — algorithm identifier types
5. `crate/clients/clap/src/` — CLI algorithm selection
6. `crate/clients/wasm/src/` — WASM crypto calls

## Step 1 — Algorithm Inventory

Identify every cryptographic algorithm used in the scanned code. For each:

- Algorithm name and key size
- Where it is used (encrypt, sign, derive, hash, MAC)
- Whether it is gated with `#[cfg(feature = "non-fips")]`

## Step 2 — FIPS Algorithm Checklist

**NIST-approved (allowed without non-fips gate):**

| Category | Approved algorithms |
|----------|-------------------|
| Symmetric encryption | AES-128, AES-192, AES-256 (GCM, CCM, CBC, CTR, KW, KWP, XTS*) |
| Asymmetric encryption | RSA-2048+, EC P-256, P-384, P-521 |
| Digital signatures | ECDSA (P-256/384/521), RSA-PSS, RSA-PKCS1v15, ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| Key encapsulation | ML-KEM (FIPS 203) |
| Hash functions | SHA-256, SHA-384, SHA-512, SHA-3 variants |
| MAC | HMAC-SHA-256/384/512, AES-GMAC, CMAC |
| KDF | HKDF, PBKDF2, SP 800-108 (Counter, Feedback, Pipeline) |
| RNG | CTR_DRBG, HASH_DRBG (via OpenSSL FIPS provider) |

*AES-XTS is non-FIPS in this codebase (`non-fips` feature).

**NOT approved (must be gated with `#[cfg(feature = "non-fips")]`):**

- MD5, SHA1 for any security purpose
- DES, 3DES, RC4, Blowfish, ChaCha20
- AES-XTS (not in FIPS 140-3 approved mode list for this provider)
- Covercrypt, Redis-findex (non-standard, non-FIPS)
- PQC algorithms beyond ML-KEM/ML-DSA/SLH-DSA (pre-standardization)
- EC curves outside P-256/P-384/P-521 (e.g. Curve25519, secp256k1)

## Step 3 — Feature Flag Gating Audit

For every non-approved algorithm found:

- [ ] Is it gated at the **function or module level** with `#[cfg(feature = "non-fips")]`? (correct)
- [ ] Is the gate **inline inside a function body**? (wrong — must be at function level)
- [ ] Is the corresponding route registration in `start_kms_server.rs` wrapped in `#[cfg(feature = "non-fips")] { ... }`?
- [ ] Is the dispatch arm in `dispatch.rs` gated if the operation is non-FIPS-only?
- [ ] Are CLI actions gated in `crate/clients/clap/src/`?
- [ ] Are WASM bindings gated in `crate/clients/wasm/src/wasm.rs`?

Flag any gate that is placed **inside a function body** rather than on the function itself:

```rust
// WRONG — gate is inline inside function body
fn do_crypto() {
    #[cfg(feature = "non-fips")]
    let _ = md5::compute(data);  // ← wrong position
}

// CORRECT — gate is at function level
#[cfg(feature = "non-fips")]
fn do_crypto_non_fips() {
    let _ = md5::compute(data);
}
```

## Step 4 — Key Size Enforcement

Check all key generation and import operations in `crate/server/src/core/operations/`:

| Algorithm | Minimum key size | Check location |
|-----------|-----------------|----------------|
| RSA | 2048 bits | `create.rs`, `import.rs` |
| AES | 128 bits | `create.rs` |
| EC | P-256 (256 bits) | `create.rs` |
| HMAC keys | 112 bits (NIST SP 800-131A) | `create.rs` |

Flag any operation that accepts key sizes below these minimums without rejecting them.

## Step 5 — OpenSSL Provider Init

Review `crate/server/src/openssl_providers.rs`:

- [ ] Is `apply_openssl_dir_env_if_needed()` called **before** any `Provider::try_load()` call?
- [ ] Is the FIPS provider loaded via `OnceLock` (single initialization)?
- [ ] Is the legacy provider loaded only when `non-fips` feature is active?
- [ ] Are `OPENSSL_MODULES` and `OPENSSL_CONF` env vars set before provider init?
- [ ] Is there a fallback or error if the FIPS provider fails to load in FIPS mode?

## Step 6 — Entropy / RNG

- [ ] Is `rand::rngs::OsRng` (or OpenSSL's CSPRNG) used for all key generation? Flag any use of `rand::thread_rng()` or `rand::random()` for security-sensitive operations.
- [ ] Are IVs / nonces generated from the CSPRNG, not hardcoded or derived from deterministic sources?
- [ ] Are salts for KDFs randomly generated per operation?

## Step 7 — CBOM / SBOM Currency

If `crate/crypto/build.rs` was changed (OpenSSL version update):

- [ ] `cbom/cbom.cdx.json` updated with new algorithm identifiers?
- [ ] `sbom/` SBOM updated?

## Report Format

```markdown
## FIPS Audit: [scope]

### Summary
| Check | Status |
|-------|--------|
| Algorithm inventory | ✅ / ⚠️ N issues |
| Feature flag gating | ✅ / ⚠️ N issues |
| Key size enforcement | ✅ / ⚠️ N issues |
| OpenSSL provider init | ✅ / ⚠️ N issues |
| Entropy / RNG | ✅ / ⚠️ N issues |

### Findings
[Severity + description + file + line + fix for each issue]
```

**Never auto-apply fixes — present for review.**
