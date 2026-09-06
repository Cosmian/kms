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

# HSM delegation Track B — EdDSA / X25519 key generation (partial)

## Features

### HSM

- Add a new `non-fips` feature to `cosmian_kms_interfaces`, `cosmian_kms_base_hsm`,
  and every vendor PKCS#11 loader crate (`softhsm2`, `utimaco`, `proteccio`,
  `crypt2pay`, `smartcardhsm`), gating HSM-delegated `EdDSA`/X25519 exactly like
  the existing software gating in `crate::crypto::elliptic_curves::sign`. HKDF is
  NIST-approved regardless of transport and is intentionally **not** gated (not
  yet implemented in this pass — see "Deferred" below)
- Add HSM-delegated `EdDSA` signing: new `EcCurve::Ed25519`/`Ed448` (Edwards
  curves, `CKM_EC_EDWARDS_KEY_PAIR_GEN`) and `SigningAlgorithm::Ed25519`/`Ed448`
  (`CKM_EDDSA`, pure/un-hashed signing), resolved from KMIP
  `CryptographicAlgorithm::Ed25519`/`Ed448` (KMIP 2.1 has no
  `DigitalSignatureAlgorithm` variant for `EdDSA`, unlike ECDSA). Fully
  KMIP-reachable via the existing `CreateKeyPair`/`Sign` HSM delegation paths —
  no new operation wiring required
- Add HSM-delegated X25519 key generation: new `EcCurve::X25519` (Montgomery
  curve, `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`), requested via KMIP
  `CryptographicAlgorithm::ECDH` + a `CURVE25519` `RecommendedCurve` domain
  parameter (KMIP has no dedicated "X25519" `CryptographicAlgorithm`). The
  generated key pair carries `CKA_DERIVE` instead of `CKA_SIGN`/`CKA_VERIFY`,
  since X25519 is derive-only
- `CKA_EC_PARAMS`/`CKA_KEY_TYPE` for Edwards/Montgomery curves are set correctly:
  `CKA_KEY_TYPE` is `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` (not the NIST-curve
  `CKK_EC`), and `CKA_EC_PARAMS` uses the DER-encoded `PrintableString` curve name
  (`"edwards25519"`/`"edwards448"`/`"curve25519"`), not the OID form — empirically
  verified against `SoftHSM2` 2.6.1, which rejects the OID form with
  `CKR_TEMPLATE_INCONSISTENT`

## Deferred (tracked as remaining #1157 scope)

- **HSM-delegated X25519 ECDH key agreement** (`DeriveKey` operation): no PKCS#11
  backend available in this environment (`SoftHSM2` 2.6.1, Utimaco CryptoServer
  simulator) exposes `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`, so the derive path could
  not be validated end-to-end; also requires new KMIP `DeriveKey` → HSM wiring
  (currently software-only in `derive_key.rs`)
- **HSM-delegated HKDF / SP 800-108 KDF** (`CKM_HKDF_DERIVE`,
  `CKM_SP800_108_*_KDF`): neither available simulator implements these
  mechanisms; same `DeriveKey` wiring gap as above
- **HSM-delegated message-based AEAD** (`C_MessageEncryptInit`/`EncryptMessage`/
  `MessageEncryptFinal` and `Decrypt` equivalents): neither available simulator
  exports these PKCS#11 v3.0 functions; additionally requires a session-state
  design decision (amortizing key/session setup across a KMIP batch) that is
  out of scope for this change

## Tests

- Add unit tests: NIST curve OID round-trip, Edwards/Montgomery curve parameter
  encoding (`PrintableString`, `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY`, correct
  key-pair-gen mechanism), and `SigningAlgorithm::from_kmip` resolution for
  `Ed25519`/`Ed448`
- Add `#[ignore]`d `eddsa_sign_all_curves` SoftHSM2 integration test (Ed25519 +
  Ed448), manually run against a live `SoftHSM2` 2.6.1 token: key generation,
  sign/verify via an independent OpenSSL check, determinism (unlike ECDSA,
  `EdDSA` is deterministic), and tamper-detection
- X25519 key generation, HKDF, and message-based AEAD have **no** integration
  test: neither `SoftHSM2` nor the Utimaco CryptoServer simulator implement the
  required mechanisms in this environment (confirmed via `pkcs11-tool -M` against
  both). Only mocked/parameter-only unit tests are provided for the pieces that
  were implemented (X25519 key generation); HKDF, SP 800-108, and message-based
  AEAD are not implemented at all in this pass (see "Deferred" above)

---

Partially addresses #1157: `EdDSA` signing (Ed25519/Ed448) is complete and
validated live; X25519 key generation is implemented but unvalidated
end-to-end (no available HSM simulator supports its key-pair-gen mechanism);
X25519 ECDH derive, HKDF/SP 800-108 KDF, and message-based AEAD remain open,
tracked as remaining scope on #1157.

## Bug Fixes

### HSM

- Preserve EC-family HSM metadata when reconstructing KMIP objects: Ed25519/Ed448
  keys now retain their correct signing algorithm, X25519 keys are exposed as
  `ECDH` with `DeriveKey`, sensitive EC keys remain typed as EC keys, and
  `GetAttributes` now includes `key_format_type` plus curve domain parameters so
  downstream policy checks still enforce the configured curve whitelist
  ([#1169](https://github.com/Cosmian/kms/pull/1169))
- Reject HSM-backed X25519 key-pair creation from the public `HSM` trait until a
  matching key-agreement / `DeriveKey` path exists, avoiding persistence of
  derive-only keys that the current API cannot use
  ([#1169](https://github.com/Cosmian/kms/pull/1169))
- Include Edwards and Montgomery PKCS#11 key types in EC list/retrieve flows,
  accept alternate DER-OID encodings for Ed25519/Ed448/X25519 `CKA_EC_PARAMS`,
  preserve raw uncompressed `CKA_EC_POINT` values, propagate `CKA_START_DATE` /
  `CKA_END_DATE` read failures instead of silently dropping rotation metadata,
  and make sensitive EC private keys non-extractable when `CKA_SENSITIVE=true`
  ([#1169](https://github.com/Cosmian/kms/pull/1169))
- Fix delegated signing mechanism selection for HSM-backed keys: pre-digested
  ECDSA now uses raw `CKM_ECDSA`, pre-digested RSA-PSS now uses raw
  `CKM_RSA_PKCS_PSS`, explicit MGF1 hash choices are preserved, and missing
  request parameters now fall back to key-aware defaults instead of incorrectly
  assuming RSA/SHA-256 for EC or EdDSA keys
  ([#1169](https://github.com/Cosmian/kms/pull/1169))

### CLI

- Make `ckms ec sign` send curve-appropriate KMIP `CryptographicParameters`
  automatically for HSM-delegated ECDSA / EdDSA signing, keeping the command
  behavior aligned with the server-side delegated signing path and rejecting
  non-signing curves such as X25519/X448
  ([#1169](https://github.com/Cosmian/kms/pull/1169))

## Documentation

### Docs

- Align the HSM operations guide with actual server-enforced curve policy
  (P-256/P-384/P-521 for FIPS EC key generation), document the pre-hashed
  delegated signing behavior for ECDSA and RSA-PSS, and mark
  `ADR-2026-09-05-hsm-track-a-rsa-pss-scope-decision` as superseded by the
  later EC/ECDSA completion ADR ([#1169](https://github.com/Cosmian/kms/pull/1169))
