# PKCS#11 v3.0 rollout: provider interfaces, mechanisms, tests

## Features

### HSM

- Implement the PKCS#11 v3.0 "interfaces" discovery entry points,
  `C_GetInterfaceList`/`C_GetInterface`, in the KMS's own PKCS#11 provider library
  (`libcosmian_pkcs11`). `CK_INFO.cryptokiVersion` is bumped from 2.40 to 3.1. The
  existing `C_GetFunctionList` (v2.40) entry point is unchanged, so every existing
  consumer (Veracrypt, LUKS, Cryhod, Oracle TDE, OpenSSH) keeps working without any
  configuration or code change
  ([#1156](https://github.com/Cosmian/kms/issues/1156))
- Add native `CKM_AES_GCM` support to the PKCS#11 provider library: authenticated
  encryption/decryption with AAD, using the `ciphertext || 16-byte tag` framing
  convention. `ulTagBits` must be 128 (the only tag length supported by the KMS's
  AES-GCM backend); IV is bounded to 1-128 bytes and AAD to 0-1 MiB
  ([#1156](https://github.com/Cosmian/kms/issues/1156))
- Confirm `CKM_EDDSA`/`CKM_ECDSA` were already fully supported prior to this change; no
  code change was required for those two mechanisms

## Fixes

### HSM

- Fix two PKCS#11 v3.x conformance bugs that made Ed25519/Ed448 keys unusable through
  any external, `CKA_KEY_TYPE`-aware PKCS#11 client (e.g. OpenSC's `pkcs11-tool`),
  surfaced by the new `pkcs11-tool` conformance tier (see Testing below):
  - `to_ck_key_type()` now reports `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` for
    Ed25519/Ed448/X25519/X448 instead of the generic `CKK_EC`, per PKCS#11 v2.40+/v3.x
  - `key_algorithm_from_attributes()` now recognises KMIP's dedicated
    `CryptographicAlgorithm::Ed25519`/`Ed448` values (previously only `EC`/`ECDH` were
    handled, so every Ed25519/Ed448 key object load failed server-side)
  - NIST/SECG curves (P-256/P-384/P-521/secp256k1/secp224k1) are unaffected and keep
    reporting `CKK_EC`, preserving backward compatibility with existing consumers
    (OpenSSH, Veracrypt, LUKS)

## Documentation

- Add a new "PKCS#11 provider module" reference page documenting the v3.0 interfaces
  discovery model, the `CKM_AES_GCM` mechanism, and the backward-compatibility
  guarantee (`documentation/docs/integrations/pkcs11_provider.md`), linked from the
  Veracrypt, LUKS, and OpenSSH integration pages
- Add ADR-2026-09-04 recording the provider-side PKCS#11 v3.0 rollout decision
  (interfaces discovery, backend-registration idempotency, non-null v3.0 function
  list, `CKM_AES_GCM` parameter bounds)

## Testing

- Add 7 unit tests for `CKM_AES_GCM` mechanism parsing/validation (valid IV/AAD, empty
  AAD, invalid tag bits, zero/oversized IV, oversized AAD, wrong parameter size)
- Add 2 live-KMS integration tests: a full `CKM_AES_GCM` encrypt/decrypt round trip via
  raw `C_EncryptInit`/`C_Encrypt`/`C_DecryptInit`/`C_Decrypt` calls, and a
  `C_GetInterfaceList`/`C_GetInterface` discovery/argument-validation test
- Add 3 mandatory PKCS#11 signing conformance tests in `cosmian_pkcs11`, each
  exercising a real `CliBackend::remote_sign` request (the same code path used by
  `C_Sign`) against a KMS server backed by SoftHSM2 with a Key-Encryption-Key
  (HSM-KEK), so every key is transparently AES-wrapped by an HSM-resident KEK before
  being persisted:
  - `test_hsm_kek_ecdsa_p256_sign` — `CKM_ECDSA` on a NIST P-256 key
  - `test_hsm_kek_ecdsa_secp256k1_sign` — `CKM_ECDSA` on a secp256k1 key (non-FIPS
    curve; runs only in the non-fips build, consistent with
    `algorithm_policy::validate_curve`'s FIPS curve allow-list)
  - `test_hsm_kek_eddsa_ed25519_sign` — `CKM_EDDSA` on a Curve25519/Ed25519 key
  - Each test also calls the KMIP `SignatureVerify` operation against the freshly
    created public key and asserts the signature is cryptographically valid, so a
    wrong signature format, digest, or curve handling fails loudly instead of passing
    a shape-only ("non-empty") check
  - Wired into `.mise/tasks/test/hsm-softhsm2` as a 4th test invocation (non-fips
    variant only), reusing the existing SoftHSM2 setup/teardown helpers
- Add a 4th, external-client conformance tier: `mise run test:hsm-pkcs11-tool`
  (`.mise/scripts/test/test_hsm_kek_pkcs11_sign.sh`) issues the same 3 signing
  requests through OpenSC's `pkcs11-tool` — an independently-implemented, non-Cosmian
  PKCS#11 v3 client — against a real (not in-process) KMS server with a SoftHSM2
  HSM-KEK, closing the "we only tested our own client" gap left by the in-process
  Rust tests above:
  - Bootstraps the HSM-KEK via `ckms sym keys create --key-id "hsm::<slot>::kek"`,
    restarts the server with `key_encryption_key` set, then creates the 3 test
    keypairs (`ckms ec keys create --curve nist-p256|secp256k1|ed25519`)
  - Signs via `pkcs11-tool --module libcosmian_pkcs11 --sign --mechanism
    ECDSA|EDDSA`, i.e. a real PKCS#11 v3 `C_Sign` call into the KMS's own provider
    library, which in turn calls the KMS server's `Sign` KMIP operation
  - Verifies every signature via `ckms ec sign-verify` (the KMIP `SignatureVerify`
    operation), for a genuine cryptographic correctness check
  - `pkcs11-tool` is a hard requirement for this tier: the task fails loudly
    (`require_cmd pkcs11-tool`) if it is not installed, and any `pkcs11-tool` failure
    aborts the script immediately (`set -euo pipefail`) — there is no silent fallback
    to `ckms ec sign`, so a real PKCS#11 v3 conformance regression cannot pass unnoticed
  - **Findings, both fixed by this change**: this new test tier surfaced two genuine
    PKCS#11 v3.x conformance bugs in the Ed25519 code path, both now fixed:
    1. `crate/clients/pkcs11/module/src/traits/key_algorithm.rs::to_ck_key_type()`
       reported Ed25519/Ed448/X25519/X448 keys as `CKK_EC` instead of the PKCS#11
       v2.40+/v3.x-correct `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY`, so OpenSC's
       `CKA_KEY_TYPE`-aware object lookup for `--mechanism EDDSA` never matched the
       key. NIST/SECG curves (P-256/P-384/P-521/secp256k1/secp224k1) keep reporting
       `CKK_EC`, so backward compatibility with existing consumers (OpenSSH,
       Veracrypt, LUKS) is preserved
    2. `crate/clients/pkcs11/provider/src/kms_object.rs::key_algorithm_from_attributes()`
       only recognised the generic `CryptographicAlgorithm::EC`/`ECDH` KMIP values.
       KMIP 2.1 assigns Ed25519/Ed448 their own dedicated `CryptographicAlgorithm`
       values (distinct from `EC`/`ECDH`, see
       `crate/kmip/src/kmip_2_1/requests/create_key_pair.rs::build_algorithm_from_curve`),
       so every Ed25519/Ed448 key object load failed server-side with "unsupported
       cryptographic algorithm", regardless of the `CKK_EC_EDWARDS` fix above — this
       was the actual root cause of the `pkcs11-tool` "Private/secret key not found"
       failure
  - All 3 curves (ECDSA P-256, ECDSA secp256k1, EdDSA Ed25519) now sign successfully
    end-to-end through real `pkcs11-tool --sign` calls, verified via `ckms ec
    sign-verify`

---

Closes #1156
