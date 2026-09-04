# HSM delegation Track A — RSA-PSS signing

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

## Documentation

- Document HSM-delegated RSA-PSS signing in
  `documentation/docs/hsm_support/hsm_operations.md`
- Add ADR-2026-09-05 recording the #1154 scope decision: implement RSA-PSS signing
  fully in this change; defer EC key generation, ECDSA signing, and HSM-delegated
  PBKDF2 derivation to a follow-up issue (larger surface: new key material types,
  curve/FIPS gating, and new HSM-resident object-creation routing)

## Tests

- Add unit tests for the new `SigningAlgorithm`/`HsmSigningAlgorithm` PSS variants and
  PKCS#11 `CK_RSA_PKCS_PSS_PARAMS` mechanism dispatch
- Add an `#[ignore]`d SoftHSM2 integration test
  (`rsa_pss_sign_all_algorithms`/`test_hsm_softhsm2_rsa_pss_sign_all_algorithms`)
  exercising RSA-PSS signing across SHA-256/384/512, default and explicit salt
  lengths (including deterministic `salt_length: 0`), and confirming non-zero-salt
  PSS is randomized

---

Partially closes #1154 (RSA-PSS signing sub-item only; EC key generation, ECDSA
signing, and PBKDF2 HSM derivation remain open and are tracked in a follow-up issue).
