---
title: "ADR-2026-10-09: Wire KmsRng into ML-KEM/ML-DSA Keygen and Document Hybrid KEM Entropy Limits"
status: "Accepted"
date: "2026-10-09"
authors: "cryptographic engineers, security auditors, KMS contributors"
tags: ["architecture", "decision", "crypto", "pqc", "fips", "rng", "openssl"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-09: Wire KmsRng into ML-KEM/ML-DSA Keygen and Document Hybrid KEM Entropy Limits

## Status

Proposed | **Accepted** | Rejected | Superseded | Deprecated

## Context

Eviden KMS implements post-quantum cryptographic (PQC) operations using OpenSSL 3.6.2, including ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid KEM schemes (`X25519MLKEM768`, `X448MLKEM1024`).

Two architectural challenges arose across PQC key generation, entropy sourcing, and compliance claims:

1. **Entropy Sourcing & NIST SP 800-133r3 / SP 800-90A/B/C alignment**:
   `KmsRng` was passed as an optional argument to PQC key generation functions (`create_ml_kem_key_pair`, `create_ml_dsa_key_pair`, `create_slh_dsa_key_pair`, `create_hybrid_kem_key_pair`), but the underlying implementation in `pqc/mod.rs` discarded `rng` (`let _ = rng;`) and called OpenSSL `EVP_PKEY_Q_keygen`. Consequently, keys were generated directly by OpenSSL's internal DRBG without using the server's central `KmsRng` abstraction.
2. **Hybrid KEM Entropy Limitations**:
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

3. **Retain Minimal Unsafe FFI Boundaries for Key Generation**:
   - Direct OpenSSL 3.x FFI calls (`EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params`, `EVP_PKEY_generate`) remain in `pqc/mod.rs` until upstream `rust-openssl` exposes safe parameter-setting keygen abstractions.

4. **Clarify Hybrid KEM Architectural Limits in Documentation**:
   - Document in `documentation/docs/certifications_and_compliance/cryptographic_algorithms/random_number_generation.md` why hybrid KEMs cannot accept an external seed from `KmsRng`:
     OpenSSL 3.6.2 implements composite key management in `providers/implementations/keymgmt/mlx_kmgmt.c`. Its parameter list `mlx_gen_set_params_list` only supports `OSSL_PKEY_PARAM_PROPERTIES` and does not provide a `"seed"` parameter. OpenSSL generates both classical and post-quantum key components atomically inside `mlx_kem_gen`.
   - Clarify that hybrid KEMs must draw entropy from OpenSSL's default DRBG and cannot inherit ESV properties from `KmsRng`.

## Consequences

### Positive

- **POS-001**: Deterministic, reproducible key generation from external seeds is now available for ML-KEM and ML-DSA, aligning with FIPS 203 §7.1 and FIPS 204 §6.1.
- **POS-002**: Transparent compliance documentation prevents false customer or auditor assumptions regarding ESV certification or hybrid KEM seeding.
- **POS-003**: All `EVP_PKEY_CTX` allocations are protected by RAII drop guards (`PKeyCtxGuard`), eliminating memory leak risks on error return paths.

### Negative

- **NEG-001**: Direct FFI declarations for OpenSSL 3.x keygen functions must be maintained in `pqc/mod.rs` until upstream `rust-openssl` merges safe abstractions.
- **NEG-002**: Hybrid KEM algorithms (`X25519MLKEM768`, `X448MLKEM1024`) cannot be seeded by `KmsRng`, creating an asymmetry in entropy flow between pure PQC algorithms and hybrid KEMs.

## Alternatives Considered

### Retain Unseeded `EVP_PKEY_Q_keygen` for All PQC Algorithms

- **ALT-001 Description**: Continue discarding `rng` in `pqc_keygen` and rely solely on OpenSSL's internal OS-seeded DRBG for ML-KEM and ML-DSA.
- **ALT-002 Rejection Reason**: Prevented Eviden KMS from ever attaching an ESV-validated physical entropy source to PQC key generation. Additionally, having an unused `rng` parameter in the public API misled callers about entropy sourcing.

### Attempt Out-of-Band Generation of Hybrid KEM Sub-keys

- **ALT-003 Description**: Independently generate an X25519/X448 key and an ML-KEM key using `KmsRng`, export their raw bytes, and attempt to assemble them into a composite OpenSSL `EVP_PKEY`.
- **ALT-004 Rejection Reason**: OpenSSL 3.6.2 does not expose a public composite key import interface for raw concatenated sub-keys via generic `EVP_PKEY` APIs, and bypassing OpenSSL's composite key lifecycle creates severe maintenance and validation risks across OpenSSL minor versions.

## Implementation Notes

- **IMP-001**: `OSSL_PARAM` construction in `pqc_keygen_seeded` uses the C-compatible struct layout (`data_type: 5` for `OSSL_PARAM_OCTET_STRING`, `return_size: usize::MAX` for `OSSL_PARAM_UNMODIFIED`) terminated by a null entry.
- **IMP-002**: Seeded keygen functions zeroize seed buffers on drop via `ZeroizeOnDrop` wrappers.
- **IMP-003**: Deterministic keygen tests verify that identical seeds produce identical PKCS#8 DER bytes across ML-KEM and ML-DSA variants.

## References

- **REF-001**: NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*
- **REF-002**: NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard (ML-DSA)*
- **REF-003**: NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*
- **REF-004**: OpenSSL 3.6.2 implementation files: `providers/implementations/keymgmt/ml_kem_kmgmt.c`, `ml_dsa_kmgmt.c`, `mlx_kmgmt.c`
- **REF-005**: Codebase files: `crate/crypto/src/crypto/pqc/mod.rs`, `crate/crypto/src/crypto/pqc/ml_kem.rs`, `crate/crypto/src/crypto/pqc/ml_dsa.rs`, `crate/crypto/src/crypto/rng/mod.rs`, `documentation/docs/certifications_and_compliance/cryptographic_algorithms/random_number_generation.md`
