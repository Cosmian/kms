---
title: "ADR-2026-09-05: HSM delegation Track A — RSA-PSS scope decision"
status: "Superseded"
date: "2026-09-05"
authors: "HSM integration contributors"
tags: ["architecture", "decision", "hsm", "pkcs11", "signing", "backward-compatibility"]
supersedes: ""
superseded_by: "2026-09-06-hsm-track-a-ec-ecdsa-completion-pbkdf2-deferral"
---

## Status

Superseded by [ADR-2026-09-06](2026-09-06-hsm-track-a-ec-ecdsa-completion-pbkdf2-deferral.md)

## Context

Issue [#1154](https://github.com/Cosmian/kms/issues/1154) ("HSM delegation Track A:
EC / RSA-PSS / PBKDF2") bundles four independent sub-items and its own description
estimates "multiple weeks across the 4 sub-items":

1. A generic EC key type plus native `C_GenerateKeyPair` EC key generation.
2. HSM-delegated ECDSA signing (depends on item 1).
3. HSM-delegated RSA-PSS signing.
4. HSM-delegated PBKDF2 derivation via `CKM_PKCS5_PBKD2`.

Investigation of the existing consumer-side HSM code
(`crate/interfaces/src/hsm/interface.rs`, `crate/hsm/base_hsm/src/session/session_impl.rs`,
`crate/server/src/core/operations/sign.rs`, `crate/server/src/core/operations/derive_key.rs`)
found the four sub-items have very different blast radii:

- **RSA-PSS signing** slots directly into the existing `SigningAlgorithm` /
  `HsmSigningAlgorithm` enums and the pre-existing `CryptoOpSpec` routing in
  `sign.rs`, which is already fully generic over the signing algorithm and only
  requires the target key to be an RSA private key — a check that remains valid for
  PSS. `pkcs11-sys` 0.2.25 already binds `CK_RSA_PKCS_PSS_PARAMS` and the
  `CKM_SHA{256,384,512}_RSA_PKCS_PSS` mechanism constants, so no FFI fork is needed.
  **Zero new key types, zero new object-creation code paths, zero changes to
  `sign.rs`/`hsm_store.rs`/`kms_hsm.rs`.**
- **EC key support** requires new `HsmKeypairAlgorithm`/`KeyMaterial`/`HsmObjectFilter`
  variants, EC curve validation, FIPS-approved-curve gating, and CLI/UI parity (sync
  rules 4.4/4.5) — a multi-file, multi-week undertaking on its own.
- **ECDSA signing** is blocked on EC key support (item 1); it cannot be implemented
  independently.
- **PBKDF2 HSM derivation** turned out not to be a simple "derive from an existing key
  handle" operation. The real PKCS#11 `CK_PKCS5_PBKD2_PARAMS` struct
  (`pkcs11-sys` 0.2.25) has `pPassword`/`ulPasswordLen` fields and is invoked via
  `C_GenerateKey`, not `C_DeriveKey`: it derives from a plaintext password buffer
  supplied directly in the call, and the *derived* key materializes as a **new**
  HSM-resident object that must be registered as a new `hsm::`-prefixed KMIP object
  (via the `ObjectsStore::create` path). This is comparably invasive to full EC
  support and not a "simple, contained" addition as initially assumed — the current
  `derive_key.rs` operation has no `CryptoOpSpec`-style HSM routing at all today.

## Decision

Split issue #1154 into two waves instead of implementing all four sub-items in one
pass:

1. **This change**: implement HSM-delegated **RSA-PSS signing** fully and additively.
   - Extend `SigningAlgorithm` (`crate/interfaces/src/crypto_oracle.rs`) with
     `RsaPssSha256/384/512 { salt_length: Option<u32> }` variants, resolved from KMIP
     `CryptographicParameters` via two paths: explicit
     `DigitalSignatureAlgorithm::RSASSAPSS`, or
     `CryptographicAlgorithm::RSA` + `PaddingMethod::PSS`. Default salt length equals
     the digest length in bytes (32/48/64), matching the existing software RSA-PSS
     convention in `crate/crypto/src/crypto/rsa/sign.rs`; `salt_length: Some(0)`
     remains valid (deterministic PSS).
   - Extend `HsmSigningAlgorithm` (`crate/hsm/base_hsm/src/session/session_impl.rs`)
     with matching variants and PKCS#11 `CK_RSA_PKCS_PSS_PARAMS` mechanism dispatch.
   - No changes to `sign.rs`, `hsm_store.rs`, or `kms_hsm.rs`: the existing
     `CryptoOpSpec` routing and RSA-private-key check already cover PSS.
2. **Deferred to a follow-up issue**: EC key generation, ECDSA signing, and
   PBKDF2 HSM derivation, given their materially larger and riskier surface (new key
   material types, curve/FIPS gating, CLI/UI sync rules, and new HSM-resident
   object-creation routing for PBKDF2). A follow-up issue should track these three
   items together, since items 1 and 2 are coupled and item 4 needs the same kind of
   "HSM creates and registers a new KMIP object" plumbing that could reasonably be
   designed once and reused.

## Consequences

- **Positive**: RSA-PSS signing ships as a small, self-contained, additive change with
  no breaking impact on any existing signing algorithm, key type, or HSM vendor
  loader; fully covered by unit tests (interfaces + base_hsm crates) and an
  `#[ignore]`d SoftHSM2 integration test mirroring the existing RSA signing test
  suite.
- **Negative**: issue #1154 is only partially closed by this change; EC key
  generation, ECDSA signing, and PBKDF2 HSM derivation remain open and should be
  tracked in a dedicated follow-up issue referencing this ADR.
- **Follow-up**: when EC key support is implemented, revisit whether PBKDF2 HSM
  derivation can share the same "create + register a new HSM-resident KMIP object"
  code path that EC key generation will need to introduce.
