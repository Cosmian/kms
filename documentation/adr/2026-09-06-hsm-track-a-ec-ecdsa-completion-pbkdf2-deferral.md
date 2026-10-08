---
title: "ADR-2026-09-06: HSM delegation Track A — EC/ECDSA completion, PBKDF2 deferral"
status: "Accepted"
date: "2026-09-06"
authors: "HSM integration contributors"
tags: ["architecture", "decision", "hsm", "pkcs11", "ec", "ecdsa", "pbkdf2", "backward-compatibility"]
supersedes: ""
superseded_by: ""
---

## Status

Accepted

## Context

[ADR-2026-09-05](./2026-09-05-hsm-track-a-rsa-pss-scope-decision.md) split issue
[#1154](https://github.com/Cosmian/kms/issues/1154) into two waves: RSA-PSS signing
(wave 1, shipped) and EC key generation + ECDSA signing + PBKDF2 HSM derivation
(wave 2, deferred). This ADR closes wave 2.

Implementation and manual validation against a live **SoftHSM2 2.7.0** token
(the only PKCS#11 HSM backend readily available in this environment) established:

- **EC key generation** (`C_GenerateKeyPair` with `CKM_EC_KEY_PAIR_GEN`) and
  **ECDSA signing** (`C_Sign` with `CKM_ECDSA_SHA{256,384,512}`) are both fully
  supported by SoftHSM2 for the four FIPS-approved NIST curves (P-224, P-256,
  P-384, P-521).
- **PBKDF2 HSM derivation** (`CKM_PKCS5_PBKD2`) is **not implemented by SoftHSM2
  2.7.0** (confirmed via `pkcs11-tool --module <lib> -M`, which does not list
  `PKCS5_PBKD2` among supported mechanisms). Since SoftHSM2 is the only backend
  available for end-to-end validation in this environment, and the user
  explicitly requested SoftHSM2 as the validation backend, PBKDF2 HSM
  derivation cannot be implemented and verified against a real device here.

## Decision

1. **Implement EC key generation and ECDSA signing fully and additively**:
   - `HsmKeypairAlgorithm::EC` (new unit variant) selects curve generation via
     the pre-existing `key_length_in_bits` parameter of `HSM::create_keypair`
     (224/256/384/521 bits ↔ P-224/P-256/P-384/P-521), mirroring how RSA already
     selects key size through that same parameter — no trait signature change.
   - New `EcCurve` enum, `KeyMaterial::EcPrivateKey`/`EcPublicKey`,
     `HsmObjectFilter::EcKey`/`EcPrivateKey`/`EcPublicKey` in
     `crate/interfaces/src/hsm/interface.rs`.
   - New `SigningAlgorithm::EcdsaSha256/384/512` in
     `crate/interfaces/src/crypto_oracle.rs`, resolved from KMIP
     `CryptographicParameters` (`DigitalSignatureAlgorithm::ECDSA` or
     `CryptographicAlgorithm::EC | ECDH | ECDSA` + hashing algorithm).
   - `crate/hsm/base_hsm/src/session/ec.rs` (new file): curve ↔ DER-OID mapping,
     curve byte-size helpers, `Session::generate_ec_key_pair`.
   - `crate/hsm/base_hsm/src/session/session_impl.rs`: EC export/metadata/key-type
     functions, ECDSA `C_Sign` dispatch. PKCS#11 ECDSA signatures are raw
     `r‖s`; a from-scratch minimal DER encoder
     (`ecdsa_raw_to_der`/`der_encode_unsigned_integer`/`der_push_length`) converts
     them to the DER `SEQUENCE { r, s }` format the rest of the codebase expects,
     keeping `openssl` out of the production dependency graph of `base_hsm`.
   - `crate/interfaces/src/hsm/hsm_store.rs`: generalized RSA-only keypair-creation
     detection (`is_rsa_keypair_creation` → `is_asymmetric_keypair_creation`) and
     the `sign`/`build_sensitive_stub_*`/`build_find_attributes`/
     `to_object_with_metadata` paths to be algorithm-generic (RSA or EC), reusing
     the RSA code shape rather than adding parallel logic.
   - `get_key_type()` (`session_impl.rs`) validates `CKA_EC_PARAMS` against the
     four FIPS-approved curves for any `CKK_EC` object and errors on unrecognized
     curves (e.g. brainpool), preserving the pre-existing invariant that HSM
     objects using algorithms/curves the KMS does not support are excluded from
     generic searches/exports — exactly as unsupported key types already were.
   - No changes needed to `create_key_pair.rs` (server) or any CLI/UI code: both
     are already algorithm-generic over RSA/EC (confirmed the KMIP EC key pair
     request builder and the server's `generate_key_pair` already handle
     `CryptographicAlgorithm::EC/ECDH/ECDSA` uniformly before this change).
2. **Defer PBKDF2 HSM derivation** to a future issue, to be revisited once a
   PBKDF2-capable PKCS#11 backend (e.g. a hardware HSM or a different software
   token) is available for end-to-end validation. No PBKDF2 code is added by
   this change.

## Consequences

- **Positive**: issue #1154 is now fully closed for EC key generation and ECDSA
  signing — additive, zero breaking changes, validated against a live SoftHSM2
  token (25/25 tests passing, including new `#[ignore]`d integration tests
  covering all 4 curves × 3 hash algorithms, DER-signature verification via an
  independent OpenSSL check, ECDSA randomization, and tamper detection).
- **Negative**: PBKDF2 HSM derivation remains unimplemented; issue #1154 is not
  100% closed by this change.
- **Follow-up**: track PBKDF2 HSM derivation in a dedicated issue once a
  PBKDF2-capable PKCS#11 backend is available for validation.
