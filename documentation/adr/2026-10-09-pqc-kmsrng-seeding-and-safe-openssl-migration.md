---
title: "ADR-2026-10-09: Wire KmsRng into ML-KEM/ML-DSA Keygen, Resolve Safe OpenSSL Migration (Issue #894 / #1251), and Document Hybrid KEM Limits"
status: "Accepted"
date: "2026-10-09"
authors: "cryptographic engineers, security auditors, KMS contributors"
tags: ["architecture", "decision", "crypto", "pqc", "fips", "rng", "openssl"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-09: Wire KmsRng into ML-KEM/ML-DSA Keygen, Resolve Safe OpenSSL Migration (Issue #894 / #1251), and Document Hybrid KEM Limits

## Status

Proposed | **Accepted** | Rejected | Superseded | Deprecated

## Context

Eviden KMS implements post-quantum cryptographic (PQC) operations using OpenSSL 3.6.2, including ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid KEM schemes (`X25519MLKEM768`, `X448MLKEM1024`).

Three interrelated architectural challenges arose across PQC key generation, safe crate boundaries, and compliance claims:

1. **Entropy Sourcing & NIST SP 800-133r3 / SP 800-90A/B/C alignment**:
   `KmsRng` was passed as an optional argument to PQC key generation functions (`create_ml_kem_key_pair`, `create_ml_dsa_key_pair`, `create_slh_dsa_key_pair`, `create_hybrid_kem_key_pair`), but the underlying implementation in `pqc/mod.rs` discarded `rng` (`let _ = rng;`) and called OpenSSL `EVP_PKEY_Q_keygen`. Consequently, keys were generated directly by OpenSSL's internal DRBG without using the server's central `KmsRng` abstraction.
2. **Issue #894 ("Reuse crate openssl for the PQC implementation")**:
   Early PQC implementations used raw OpenSSL FFI calls with manual BIO allocations (`i2d_PrivateKey_bio`, `i2d_PUBKEY_bio`, `BIO_s_mem`, `BIO_get_mem_data`, manual `BioGuard`), two-pass manual buffer sizing (`EVP_PKEY_get_raw_private_key`, `EVP_PKEY_get_raw_public_key`), and raw DER parsing (`d2i_AutoPrivateKey`, `d2i_PUBKEY`) marked with `#[expect(unsafe_code)]`. In `openssl` crate 0.10.81, native safe methods exist on `PKey<T>` (`private_key_to_pkcs8`, `public_key_to_der`, `raw_private_key`, `raw_public_key`, `private_key_from_der`, `public_key_from_der`), making raw FFI BIO wrappers and custom `d2i` implementations obsolete.
3. **Issue #1251 ("PQC keygen and KEM unsafe blocks blocked on rust-openssl")**:
   While serialization and raw extraction can be migrated to safe `openssl` methods, `rust-openssl` currently lacks safe bindings for named algorithm keygen initialization, setting generic keygen parameters (`OSSL_PARAM`), executing key generation (`EVP_PKEY_generate`), KEM encapsulation/decapsulation, and raw key loading for hybrid curves. Clear tracking against upstream PRs is required to maintain minimal `unsafe` footprint.
4. **Hybrid KEM Entropy Limitations**:
   Questions arose regarding whether hybrid KEMs (X25519-ML-KEM-768 and X448-ML-KEM-1024) can benefit from `KmsRng` seed injection or future Entropy Source Validation (ESV) certificates.

## Decision

We chose to:

1. **Wire `KmsRng` Seed Injection into ML-KEM and ML-DSA Keygen**:
   - Implement `pqc_keygen_seeded(name: &CString, seed: &[u8]) -> Result<PKey<Private>, CryptoError>`.
   - When `rng: Option<&KmsRng>` is `Some`:
     - **ML-KEM**: Draw 64 bytes of entropy ($d, z$) via `generate_pqc_seed(rng, 64)?` per FIPS 203 §7.1 and inject it via `OSSL_PARAM_OCTET_STRING` under key `"seed"` (`OSSL_PKEY_PARAM_ML_KEM_SEED`).
     - **ML-DSA**: Draw 32 bytes of entropy ($\xi$) via `generate_pqc_seed(rng, 32)?` per FIPS 204 §6.1 and inject it via `OSSL_PARAM_OCTET_STRING` under key `"seed"` (`OSSL_PKEY_PARAM_ML_DSA_SEED`).
   - When `rng` is `None`, fall back to unseeded `EVP_PKEY_Q_keygen` drawing from OpenSSL's internal DRBG.
   - Guard `EVP_PKEY_CTX` with `PKeyCtxGuard` implementing RAII `EVP_PKEY_CTX_free` on drop.

2. **Keep SLH-DSA Production Keygen Unseeded**:
   - OpenSSL's SLH-DSA provider supports a `"seed"` parameter, but `EVP_PKEY-SLH-DSA(7)` explicitly restricts its use to testing and CAVP/KAT validation.
   - For production stability and security standard compliance, SLH-DSA key generation uses OpenSSL's DRBG directly via `EVP_PKEY_Q_keygen`.

3. **Resolve Issue #894 via Safe `openssl::pkey::PKey` APIs**:
   - Completely delete `BioGuard` and the manual BIO functions `evp_pkey_to_pkcs8_der` and `evp_pkey_to_spki_der`.
   - Eliminate manual two-pass raw key extraction functions `evp_pkey_get_raw_private` and `evp_pkey_get_raw_public`.
   - Rewrite `pqc_private_key_pkcs8_to_raw` and `pqc_public_key_spki_to_raw` without `unsafe` using `PKey::private_key_from_der` and `PKey::public_key_from_der`.
   - Convert raw pointers to safe `PKey<Private>` via `PKey::from_ptr` (using direct workspace dependency `foreign_types::ForeignType`) immediately after generation.

4. **Audit and Document Issue #1251 Remaining `unsafe` Blocks**:
   - Explicitly annotate remaining FFI declarations (`EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params`, `EVP_PKEY_generate`, and hybrid raw loading `EVP_PKEY_new_raw_*_key_ex`) with references to Issue #1251 and upstream `rust-openssl` PRs (#2649, #2646, #2636, #2611).

5. **Clarify Hybrid KEM Architectural Limits in Documentation**:
   - Document in `documentation/docs/certifications_and_compliance/cryptographic_algorithms/pqc_entropy_compliance.md` why hybrid KEMs cannot accept an external seed from `KmsRng`:
     OpenSSL 3.6.2 implements composite key management in `providers/implementations/keymgmt/mlx_kmgmt.c`. Its parameter list `mlx_gen_set_params_list` only supports `OSSL_PKEY_PARAM_PROPERTIES` and does not provide a `"seed"` parameter. OpenSSL generates both classical and post-quantum key components atomically inside `mlx_kem_gen`.
   - Clarify that hybrid KEMs must draw entropy from OpenSSL's default DRBG and cannot inherit ESV properties from `KmsRng`.

## Consequences

### Positive

- **POS-001**: Deterministic, reproducible key generation from external seeds is now available for ML-KEM and ML-DSA, aligning with FIPS 203 §7.1 and FIPS 204 §6.1.
- **POS-002**: Elimination of manual BIO buffers, raw pointer manipulations, and manual length checks in key serialization and raw extraction, significantly reducing attack surface and risk of memory safety bugs.
- **POS-003**: Elimination of `#[expect(unsafe_code)]` from `pqc_private_key_pkcs8_to_raw` and `pqc_public_key_spki_to_raw`.
- **POS-004**: Transparent compliance documentation prevents false customer or auditor assumptions regarding ESV certification or hybrid KEM seeding.
- **POS-005**: All `EVP_PKEY_CTX` allocations are protected by RAII drop guards (`PKeyCtxGuard`), eliminating memory leak risks on error return paths.

### Negative

- **NEG-001**: Direct FFI declarations for OpenSSL 3.x functions (`EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params`, `EVP_PKEY_generate`) must be maintained in `pqc/mod.rs` until upstream `rust-openssl` merges safe abstractions.
- **NEG-002**: Hybrid KEM algorithms (`X25519MLKEM768`, `X448MLKEM1024`) cannot be seeded by `KmsRng`, creating an asymmetry in entropy flow between pure PQC algorithms and hybrid KEMs.

## Alternatives Considered

### Retain Unseeded `EVP_PKEY_Q_keygen` for All PQC Algorithms

- **ALT-001 Description**: Continue discarding `rng` in `pqc_keygen` and rely solely on OpenSSL's internal OS-seeded DRBG for ML-KEM and ML-DSA.
- **ALT-002 Rejection Reason**: Prevented Eviden KMS from ever attaching an ESV-validated physical entropy source to PQC key generation. Additionally, having an unused `rng` parameter in the public API misled callers about entropy sourcing.

### Attempt Out-of-Band Generation of Hybrid KEM Sub-keys

- **ALT-003 Description**: Independently generate an X25519/X448 key and an ML-KEM key using `KmsRng`, export their raw bytes, and attempt to assemble them into a composite OpenSSL `EVP_PKEY`.
- **ALT-004 Rejection Reason**: OpenSSL 3.6.2 does not expose a public composite key import interface for raw concatenated sub-keys via generic `EVP_PKEY` APIs, and bypassing OpenSSL's composite key lifecycle creates severe maintenance and validation risks across OpenSSL minor versions.

### Custom C-FFI Shims instead of Native `openssl::pkey::PKey`

- **ALT-005 Description**: Retain the existing BIO helpers and encapsulate them in a separate C file or unsafe submodule.
- **ALT-006 Rejection Reason**: Contradicts the project goal (Issue #894) of minimizing custom `unsafe` code when safe, battle-tested methods (`PKey::private_key_to_pkcs8`, `PKey::raw_private_key`) are readily available in `openssl` 0.10.81.

## Implementation Notes

- **IMP-001**: `OSSL_PARAM` construction in `pqc_keygen_seeded` uses the C-compatible struct layout (`data_type: 5` for `OSSL_PARAM_OCTET_STRING`, `return_size: usize::MAX` for `OSSL_PARAM_UNMODIFIED`) terminated by a null entry.
- **IMP-002**: Unit tests in `crate/crypto/src/crypto/pqc/mod.rs` verify determinism: identical seeds produce identical PKCS#8 DER and SPKI DER bytes for ML-KEM-768 and ML-DSA-65.
- **IMP-003**: End-to-end seeded roundtrips in `ml_kem.rs` (encapsulate/decapsulate) and `ml_dsa.rs` (sign/verify) ensure keys generated with `KmsRng` seeds are fully functional for cryptographic operations.

## References

- **REF-001**: GitHub Issue #894: *Reuse crate openssl for the PQC implementation*
- **REF-002**: GitHub Issue #1251: *PQC keygen and KEM unsafe blocks blocked on rust-openssl*
- **REF-003**: NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*
- **REF-004**: NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard (ML-DSA)*
- **REF-005**: NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*
- **REF-006**: OpenSSL 3.6.2 implementation files: `providers/implementations/keymgmt/ml_kem_kmgmt.c`, `ml_dsa_kmgmt.c`, `mlx_kmgmt.c`
- **REF-007**: Codebase files: `crate/crypto/src/crypto/pqc/mod.rs`, `crate/crypto/src/crypto/pqc/ml_kem.rs`, `crate/crypto/src/crypto/pqc/ml_dsa.rs`, `crate/crypto/src/crypto/rng/mod.rs`, `documentation/docs/certifications_and_compliance/cryptographic_algorithms/pqc_entropy_compliance.md`
