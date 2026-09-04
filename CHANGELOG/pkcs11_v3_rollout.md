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
- Implement real `C_VerifyInit`/`C_Verify`/`C_VerifyUpdate`/`C_VerifyFinal` support in
  the PKCS#11 provider module — previously these were `CKR_FUNCTION_NOT_SUPPORTED`
  stubs, meaning **no PKCS#11 client could verify a signature through
  `libcosmian_pkcs11` at all**, even though `C_Sign` fully worked. This was the most
  significant remaining PKCS#11 v3.x conformance gap identified by an audit of
  `provider/src/tests.rs` against `pkcs11-spec-v3.1.html`:
  - New `VerifyContext`/`Backend::remote_verify` mirror the existing
    `SignContext`/`Backend::remote_sign` architecture exactly
  - `C_VerifyInit` looks up an `Object::PublicKey` by handle (as opposed to
    `C_SignInit`'s `Object::PrivateKey` lookup) and populates `Session::verify_ctx`
  - Verification is a KMIP `SignatureVerify` round trip through the KMS server (no new
    local crypto dependency), reusing the exact same `SignatureAlgorithm` → KMIP
    `CryptographicParameters`/digest mapping already used for `C_Sign`
  - A failed verification (`ValidityIndicator::Invalid`) maps to the PKCS#11-mandated
    `CKR_SIGNATURE_INVALID`, not a generic operation-failure error
  - Verified end-to-end both in-process (`tests_v3::test_hsm_kek_c_verify_round_trip`,
    positive + tampered-signature negative case) and externally via
    `pkcs11-tool --verify` against all 3 mandatory curves (see Testing below)

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
    ([#1183](https://github.com/Cosmian/kms/issues/1183))
  - NIST/SECG curves (P-256/P-384/P-521/secp256k1/secp224k1) are unaffected and keep
    reporting `CKK_EC`, preserving backward compatibility with existing consumers
    (OpenSSH, Veracrypt, LUKS)

### Cryptography (`crate/crypto`)

- **Fix a KMIP `SignatureVerify`-wide correctness bug**, discovered while adding the
  `C_Verify` end-to-end test above: `ecdsa_verify()` and `ed_verify()`
  (`crate/crypto/src/crypto/elliptic_curves/verify.rs`) propagated any
  signature-parsing or verification failure (malformed DER, wrong-curve signature,
  cryptographically invalid signature) as a hard `CryptoError`, instead of mapping it
  to `ValidityIndicator::Invalid`. This affects **every** KMIP client of the `Verify`
  operation, not just PKCS#11: a tampered or malformed ECDSA/EdDSA signature caused
  the server to return a REST/codec error instead of the KMIP-mandated "Invalid"
  response, and — for PKCS#11 callers specifically — prevented `CKR_SIGNATURE_INVALID`
  from ever being returned (the client saw an opaque operation failure instead).
  RSA-PSS verification (`crate/crypto/src/crypto/rsa/verify.rs`) was already correct;
  only the elliptic-curve/EdDSA path had the gap. Fixed all 5 affected call sites to
  map signature-data errors to `false`/`Invalid` while still propagating genuine
  public-key-conversion errors as real errors
  ([#1183](https://github.com/Cosmian/kms/issues/1183))

### Nix dev environment

- Fix `shell.nix`'s `WITH_HSM=1` runtime `LD_LIBRARY_PATH` (both FIPS and non-FIPS
  branches) dropping `${pkgs.stdenv.cc.cc.lib}/lib`/`${pkgs.gcc.cc.lib}/lib` (the gcc
  runtime lib path providing `libstdc++.so.6`). Because the KMS server binary built
  inside the Nix shell carries an `RUNPATH` pointing at Nix store paths, any HSM
  PKCS#11 module dlopen'd at runtime (SoftHSM2's `libsofthsm2.so`, nix-built or the
  system apt package) — being a C++ shared object — failed to load with
  `libstdc++.so.6: cannot open shared object file: No such file or directory`,
  breaking every `WITH_HSM=1` task (`test:hsm-softhsm2`, `test:hsm-pkcs11-tool`, HSM
  vector tests) whenever the gcc lib path wasn't already on the ambient
  `LD_LIBRARY_PATH`. Found while re-running `mise run test:hsm-pkcs11-tool --variant
  non-fips` for the #1183 fix

### Cryptography — `crate/clients/pkcs11`

- **Fix a `CKM_RSA_PKCS_PSS` PKCS#11 v3.1 conformance bug**, found by external
  `pkcs11-tool` conformance testing: per PKCS#11 v3.1 §6.4.7, bare
  `CKM_RSA_PKCS_PSS` "operate[s] only on the part of PKCS #1 that involves block
  formatting and RSA, given a hash value; it does not compute a hash value on the
  message to be signed." The provider previously forwarded the caller's input as raw
  `data` to the KMS server (which then hashed it a second time), instead of treating
  it as an already-computed digest. This was invisible to every prior in-process test
  (which called `remote_sign`/`remote_verify` directly with matching, consistently
  "wrong" raw-message semantics on both the sign and verify side) but broke real
  `pkcs11-tool --sign --mechanism RSA-PKCS-PSS` calls, which correctly pass a
  pre-hashed digest per spec. Fixed
  `crate/clients/pkcs11/provider/src/kms_object.rs::signature_algorithm_to_kmip_params`
  to send `RsaPss` payloads as `digested_data` (mirroring the existing `CKM_ECDSA`
  handling), not `data`
- **Add the missing `CKA_MODULUS_BITS` attribute** on RSA private and public key
  objects (`crate/clients/pkcs11/module/src/core/object.rs`), a mandatory PKCS#11 v3.1
  attribute for RSA keys (Table 33/34) that was previously unimplemented
  (`error!("... type_ unimplemented")`/`CKR_ATTRIBUTE_TYPE_INVALID`). Found because
  OpenSC's `pkcs11-tool` reads `CKA_MODULUS_BITS` off the private key object to size
  RSA-PSS signing buffers when `--salt-len` is given explicitly
- **Fix `C_GetMechanismInfo` reporting `CKF_SIGN` alone (never `CKF_VERIFY`)** for
  every signature mechanism (`CKM_RSA_PKCS`/`CKM_SHA*_RSA_PKCS`/`CKM_RSA_PKCS_PSS`/
  `CKM_ECDSA`/`CKM_EDDSA`) — a PKCS#11 v3.1 §5.2 Table 3 conformance bug: `C_Verify`
  has been a fully working, real operation since the `C_Verify` implementation above,
  so the mechanism-info flags were stale and would mislead a spec-following client
  that checks `CKF_VERIFY` before calling `C_VerifyInit`. Found while enriching
  `ckms pkcs11 verify` with a `C_GetMechanismList`/`C_GetMechanismInfo` conformance
  check (`crate/clients/pkcs11/module/src/pkcs11.rs::C_GetMechanismInfo`)

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

- Add a unit test asserting `key_algorithm_from_attributes` resolves Ed25519/Ed448 from
  the bare `CryptographicAlgorithm` (no domain parameters) and still rejects genuinely
  unsupported algorithms
- Add a live-KMS integration test (`test_ed25519_key_discovery`) creating an Ed25519
  keypair via the standard KMIP/REST path and asserting it is returned by
  `find_all_private_keys`/`find_all_public_keys`, directly reproducing the discovery
  failure reported in ([#1183](https://github.com/Cosmian/kms/issues/1183))

### PKCS#11 v3 test reorganization and `C_Verify` conformance

- Split both PKCS#11 crates' test modules along a v2.40/v3.x boundary, per an audit
  finding that `provider/src/tests.rs` mixed baseline (v2.40-era) functionality tests
  with v3.0/v3.1-specific conformance tests, making PKCS#11 v3 coverage hard to assess
  at a glance:
  - `module/src/tests.rs` / `provider/src/tests.rs` — baseline v2.40-era tests only
    (init, slot/token/session lifecycle, SSH RSA/ECDSA-P256 signing, object discovery)
  - New `module/src/tests_v3.rs` / `provider/src/tests_v3.rs` — all PKCS#11
    v3.0/v3.1-specific tests, both moved (interface discovery, `CKO_PROFILE`,
    `CKM_AES_GCM`, HSM-KEK multi-curve signing, Ed25519 regression tests) and newly
    added by this change
- Add `test_to_ck_key_type_reports_distinct_types_per_curve_family`
  (`module/src/tests_v3.rs`): a fast regression test asserting every `KeyAlgorithm`
  variant maps to its exact expected `CK_KEY_TYPE`, explicitly covering the
  `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` fix above so any recurrence is caught in
  milliseconds instead of only by a slow, live HSM+`pkcs11-tool` run
- Add `test_unsupported_functions_return_function_not_supported`
  (`module/src/tests_v3.rs`): a table-driven test calling all ~40 v3.0
  `CKR_FUNCTION_NOT_SUPPORTED` stub functions (`C_GenerateKeyPair`, `C_WrapKey`,
  `C_UnwrapKey`, `C_DeriveKey`, all `C_Digest*`/`C_*Recover*`, `C_CopyObject`,
  `C_GetObjectSize`, `C_(Get|Set)OperationState`, `C_SessionCancel`, all 12 v3.0
  message-based functions, `C_WaitForSlotEvent`) and asserting each returns exactly
  `CKR_FUNCTION_NOT_SUPPORTED` — proving conformant non-null-function-pointer
  behavior per PKCS#11 v3.1 §5.2, not just "it compiles"
- Add `test_hsm_kek_rsa_pss_sign` (`provider/src/tests_v3.rs`): closes the previously
  untested `CKM_RSA_PKCS_PSS` mechanism (declared supported in
  `module/src/core/mechanism.rs` but never exercised by any test)
- Implement real `C_Verify` support (see Features above) and add
  `test_hsm_kek_c_verify_round_trip` (`provider/src/tests_v3.rs`, live SoftHSM2,
  `#[ignore]`/`#[serial]`): exercises `Backend::remote_verify` end-to-end — a genuine
  signature verifies successfully, and a tampered signature is rejected with
  `ModuleError::SignatureInvalid`. This test surfaced the `crate/crypto` verify bug
  fixed above (a tampered signature initially produced a hard REST/codec error
  instead of `CKR_SIGNATURE_INVALID`)
- Extend `test_key_algorithm_from_attributes_eddsa_bare_algorithm`
  (`provider/src/tests_v3.rs`) to also cover `EC`/`ECDH` + `RecommendedCurve` mapping
  and the missing-domain-parameters error case
- Extend `.mise/scripts/test/test_hsm_kek_pkcs11_sign.sh` to call
  `pkcs11-tool --verify` (real, external-client PKCS#11 v3 `C_Verify`) for all 3
  mandatory curves, in addition to the existing `ckms ec sign-verify` check — closing
  the "external client never exercised `C_Verify`" gap now that it is implemented
- Fix a stale test-name filter in `.mise/tasks/test/hsm-softhsm2`
  (`tests::test_hsm_kek` → `test_hsm_kek`): after the `tests`/`tests_v3` module split
  above, the old module-qualified filter silently matched zero tests (exit code 0,
  "success", but the 5 mandatory PKCS#11 conformance tests were never actually run) —
  a real, previously-undetected regression in the CI test infrastructure itself
- Extract the shared SoftHSM2 token-init + HSM-KEK bootstrap + server-restart
  sequence (previously duplicated inline in `test_hsm_kek_pkcs11_sign.sh`) into a new
  `hsm_kek_bootstrap()` helper in `.mise/lib/pkcs11_helpers.sh`, reused by the sign
  script and available for future HSM-KEK-backed `pkcs11-tool` conformance scripts
- Extend `test_hsm_kek_pkcs11_sign.sh` with 2 more real, external-client checks:
  - An RSA-2048 `CKM_RSA_PKCS_PSS` sign+verify via `pkcs11-tool --sign`/`--verify
    --hash-algorithm SHA256 --mgf MGF1-SHA256`, on a pre-hashed digest per the spec
    fix above — this is the test that surfaced the `CKM_RSA_PKCS_PSS`
    digested-data bug and the missing `CKA_MODULUS_BITS` attribute, both fixed above
  - A negative `C_Verify` case: a tampered P-256 ECDSA signature (one flipped byte)
    must be rejected by `pkcs11-tool --verify`, proving the external client observes
    `CKR_SIGNATURE_INVALID` distinctly from an operation error — the real,
    externally-observable analogue of the in-process
    `test_hsm_kek_c_verify_round_trip` tampered-signature case

### `ckms pkcs11 verify` full v3.1 coverage

- Enrich `ckms pkcs11 verify` (`crate/clients/clap/src/actions/pkcs11_verify.rs`) —
  previously a v2.40-era-only sanity check (`C_GetFunctionList` → `C_Initialize` →
  `C_GetSlotList` → `C_OpenSession` → `C_Login` → `C_FindObjects` →
  `C_CloseSession` → `C_Finalize`) — with real coverage of the v3.0/v3.1-specific
  API surface, all against the real, dynamically-loaded provider `.so`/`.dylib`/`.dll`
  (not a mock backend):
  - `C_GetInterfaceList`/`C_GetInterface`: two-call-convention list, default lookup,
    exact-name lookup, backward-compatible v3.0 version request, and a negative
    unknown-interface-name lookup (must be rejected, not silently accepted)
  - `C_GetInfo`: asserts `cryptokiVersion` is v3.x and no newer than the v3.1 this
    provider implements; prints manufacturer/library description/version
  - `C_GetMechanismList`/`C_GetMechanismInfo`: asserts `CKM_AES_GCM`,
    `CKM_RSA_PKCS_PSS`, `CKM_ECDSA`, and `CKM_EDDSA` are all advertised with the
    correct capability flags — this check is what surfaced the `CKF_VERIFY` mechanism-
    info bug fixed above
  - `CKO_PROFILE` self-declaration: asserts at least one conformance-profile object is
    discoverable and that every returned object's `CKA_PROFILE_ID` is one of the
    profiles this provider actually declares
  (`CKP_BASELINE_PROVIDER`/`CKP_EXTENDED_PROVIDER`/`CKP_AUTHENTICATION_TOKEN`/
    `CKP_PUBLIC_CERTIFICATES_TOKEN`)
  - Refactored `count_objects_by_class` into a shared `find_handles_by_class` helper
    so the existing object-summary counter and the new `CKO_PROFILE` attribute check
    reuse the same `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` sequence
    instead of duplicating it
  - Verified against a live JWT-authenticated KMS server
    (`test_pkcs11_verify_with_jwt_auth`) and the existing no-server negative test
    (`test_pkcs11_verify_fails_without_server`), both still passing unmodified

---

Closes #1156, #1183
