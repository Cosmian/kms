# HSM delegation Track A — RSA-PSS, EC, and ECDSA

## Features

### HSM

- Add HSM-delegated RSA-PSS signing: `SigningAlgorithm` and `HsmSigningAlgorithm` gain
  `RsaPssSha256/384/512 { salt_length: Option<u32> }` variants, resolved from KMIP
  `CryptographicParameters` (explicit `DigitalSignatureAlgorithm::RSASSAPSS`, or
  `CryptographicAlgorithm::RSA` + `PaddingMethod::PSS`). Salt length defaults to the
  digest length in bytes, matching the existing software RSA-PSS path, and
  `salt_length: 0` (deterministic PSS) remains supported. Purely additive: no changes
  to `sign.rs`, `hsm_store.rs`, `kms_hsm.rs`, or any existing signing mechanism, key
  type, or HSM vendor loader ([#1154](https://github.com/Cosmian/kms/issues/1154))
- Add HSM-delegated EC key generation: new `HsmKeypairAlgorithm::EC` variant selects
  curve generation (P-224/P-256/P-384/P-521) through the pre-existing
  `key_length_in_bits` parameter of `HSM::create_keypair`, mirroring how RSA already
  selects key size — no trait signature change. New `EcCurve` enum,
  `KeyMaterial::EcPrivateKey`/`EcPublicKey`, and `HsmObjectFilter::EcKey`/
  `EcPrivateKey`/`EcPublicKey` in `crate/interfaces/src/hsm/interface.rs`. Existing CLI
  (`ckms ec keys create`), UI, and server-side `create_key_pair.rs` code paths are
  already algorithm-generic and required no changes
- Add HSM-delegated ECDSA signing: new `SigningAlgorithm::EcdsaSha256/384/512`
  variants, dispatched to `C_Sign` with `CKM_ECDSA_SHA{256,384,512}`. PKCS#11 raw
  `r‖s` ECDSA signatures are re-encoded to DER `SEQUENCE { r, s }` to match the
  format expected elsewhere in the codebase, without adding `openssl` as a
  production dependency of `base_hsm`. Existing CLI (`ckms ec sign`) required no
  changes
- Generalize `HsmStore`'s RSA-only keypair-creation detection
  (`is_rsa_keypair_creation` → `is_asymmetric_keypair_creation`) and the `sign`/
  `build_sensitive_stub_*`/`build_find_attributes`/`to_object_with_metadata` paths
  to be algorithm-generic (RSA or EC)
- `get_key_type()` now validates `CKA_EC_PARAMS` against the four FIPS-approved
  curves for any `CKK_EC` object and errors on unrecognized curves (e.g. brainpool),
  preserving the pre-existing invariant that HSM objects using algorithms/curves the
  KMS does not support are excluded from generic searches/exports

## Documentation

- Document HSM-delegated RSA-PSS signing, EC key generation, and ECDSA signing in
  `documentation/docs/hsm_support/hsm_operations.md`
- Add ADR-2026-09-05 recording the #1154 scope decision: implement RSA-PSS signing
  fully first; defer EC key generation, ECDSA signing, and HSM-delegated PBKDF2
  derivation to a follow-up issue
- Add ADR-2026-09-06 recording the completion of EC key generation and ECDSA
  signing, and the deferral of PBKDF2 HSM derivation (SoftHSM2, the only backend
  available for end-to-end validation in this environment, does not implement
  `CKM_PKCS5_PBKD2`)

## Tests

- Add unit tests for the new `SigningAlgorithm`/`HsmSigningAlgorithm` PSS and ECDSA
  variants and PKCS#11 mechanism dispatch
- Add `#[ignore]`d SoftHSM2 integration tests, all manually run against a live
  SoftHSM2 2.7.0 token:
    - `rsa_pss_sign_all_algorithms`/`test_hsm_softhsm2_rsa_pss_sign_all_algorithms`:
      RSA-PSS across SHA-256/384/512, default and explicit salt lengths (including
      deterministic `salt_length: 0`), confirming non-zero-salt PSS is randomized
    - `generate_ec_keypair`/`test_hsm_softhsm2_generate_ec_keypair`: EC key pair
      generation for all 4 curves, exported public key point format/length, sensitive
      (non-exportable) private key enforcement
    - `ecdsa_sign_all_curves_and_hashes`/
      `test_hsm_softhsm2_ecdsa_sign_all_curves_and_hashes`: ECDSA signing across all
      4 curves × 3 hash algorithms, DER-signature verification via an independent
      OpenSSL check, randomization, and tamper-detection
    - Fixed a pre-existing SoftHSM2 install quirk uncovered while running the full
      test suite: `test_hsm_softhsm2_pkcs11_v3_capability_probe_is_additive`
      (from [#1153](https://github.com/Cosmian/kms/issues/1153)) hard-coded an
    expected Cryptoki major version of `2`, but this environment's SoftHSM2 2.7.0
    build reports `3.2` in `C_GetInfo` while still never exporting
    `C_GetInterfaceList`; the test now asserts the real behavior (no v3 interface
    support) instead of a brittle version-number check

## Fixed

- Fixed a regression in `HsmStore::find()`/`get_key_type()` interaction:
  generalizing `CKK_EC` recognition without curve validation would have caused
  HSM objects using unsupported EC curves to be incorrectly included in generic
  (`HsmObjectFilter::Any`) searches; curve validation in `get_key_type()` restores
  the original exclusion behavior

---

Closes #1154 for EC key generation and ECDSA signing (additive, zero breaking
changes, validated against a live SoftHSM2 token). PBKDF2 HSM derivation remains
open and is tracked in a follow-up issue, as SoftHSM2 does not implement
`CKM_PKCS5_PBKD2` and no other PKCS#11 backend was available for validation in
this environment.
