# PKCS#11 v3.0 consumer-side mechanisms (EdDSA, HKDF, message-AEAD) and Kryoptic conformance suite

## Features

### HSM

- Extend `HsmLib` to additively resolve the v3.0-only message-based bulk
  encrypt/decrypt entry points (`C_MessageEncryptInit`/`C_EncryptMessage`/...),
  degrading gracefully to `CKR_MECHANISM_INVALID`/`CKR_MECHANISM_PARAM_INVALID` when a
  loaded library does not support them, exactly like the existing v2.40 fallback
  ([#1153](https://github.com/Cosmian/kms/issues/1153))
- Add EdDSA (`CKM_EDDSA`, pure Ed25519 per RFC 8032) sign/verify to `Session`
- Add HKDF key derivation (`CKM_HKDF_DERIVE`) to `Session` via `derive_hkdf_key()`
- Add message-based AES-GCM encrypt/decrypt to `Session`
- Add `Session::generate_generic_secret_key()`: generates a `CKK_GENERIC_SECRET` key
  with `CKA_DERIVE = true` via `CKM_GENERIC_SECRET_KEY_GEN` — the spec-compliant way to
  produce HKDF input key material (no existing helper could do this)
- Wire RSA `SignatureVerify` through to the HSM backend (`HSM::verify`/`BaseHsm`),
  closing a pre-existing gap where it was unconditionally `NotSupported`

## Bug Fixes

### HSM

- Fix `Session::sign()`/`verify()` for EdDSA: previously sent an explicit, empty
  `CK_EDDSA_PARAMS`, which per RFC 8032 selects the distinct `Ed25519ctx` variant
  (different domain separator) rather than plain Ed25519 — not every conformant
  library implements `Ed25519ctx`. Now omits `CK_EDDSA_PARAMS` entirely
  (`pParameter = NULL`) to request the pure, spec-default Ed25519 variant
- Fix `derive_hkdf_key()`'s derived-key template: was typed `CKA_KEY_TYPE = CKK_AES`,
  which `CKM_HKDF_DERIVE` (OASIS Cryptoki v3.0 §2.5) rejects — conformant libraries
  require the output key type to be `CKK_GENERIC_SECRET`/`CKK_HKDF`. Now typed
  `CKK_GENERIC_SECRET`
- Fix `get_v3_function_list()` requesting the "PKCS 11" interface from
  `C_GetInterface` with a hardcoded `pVersion = {major: 3, minor: 0}` (an exact-match
  request per OASIS Cryptoki v3.1 §5.2). This rejected any strictly conformant
  library whose "PKCS 11" interface is versioned 3.1 or 3.2 rather than exactly 3.0,
  causing `HsmLib` to wrongly report *no* v3.0 support at all for a fully
  v3.1/v3.2-capable library. Now requests `pVersion = NULL_PTR` (any version, per
  spec) and validates the returned interface's major version is `3` before treating
  `pFunctionList` as a `CK_FUNCTION_LIST_3_0`
- Fix a Windows-only build failure (`E0793: reference to field of packed struct is
  unaligned`) in `Session::sign_with_mechanism()`/`verify_with_mechanism()`: `pkcs11-sys`
  defines `CK_MECHANISM` as `#[repr(C, packed)]` on Windows (matching the Cryptoki
  header's `pragma pack(1)`) but not on Unix, so `mechanism.mechanism` formatted
  directly in an error message implicitly took a reference into the packed struct —
  undefined behavior, rejected by rustc only on the Windows target. Now copies the
  field into a local variable before formatting it
- Fix a Windows-only CI flake in `hsm_lib::function_table_fallback_tests`: several
  `#[test]`s compile the `minimal_pkcs11.c` test fixture concurrently via `cl.exe`,
  which (unlike GCC/Clang) does not honor `-o` for the intermediate `.obj` file and
  always writes it to a single fixed name relative to the working directory —
  concurrent test threads raced on that shared `.obj`
  (`C1083: ... Permission denied`), sometimes producing a corrupted/partial `.dll`
  that later crashed the test binary with `STATUS_ACCESS_VIOLATION`. Now serializes
  the compiler invocation across the module's tests with a `Mutex`

## Testing

- Add an opt-in, dev-only PKCS#11 v3.0 conformance test suite
  (`crate/hsm/base_hsm/tests/kryoptic_conformance.rs`) built against
  [`kryoptic`](https://github.com/latchset/kryoptic), a Rust PKCS#11 v3.0
  software token maintained by Red Hat's identity team (`latchset`). Used purely as a
  conformance-test oracle (not a supported production HSM backend — no wizard/model
  entry): fetched and built out-of-tree from its published crates.io release to avoid a
  `rusqlite` version conflict with `crate/server_database`. The fetch/build step lives
  entirely in `.mise/lib/kryoptic.sh::kryoptic_build_cdylib` (mirroring
  `.mise/lib/softhsm2.sh`), which exports the built cdylib path as `KRYOPTIC_PKCS11_LIB`;
  the test reads it from the environment exactly like `SOFTHSM2_PKCS11_LIB` — no Rust
  code in `cosmian_kms_base_hsm` builds `kryoptic`. Bootstraps a fresh token
  (`C_InitToken`/`C_InitPIN`) via the v3.0 `CK_FUNCTION_LIST` (Kryoptic exports only
  `C_GetFunctionList`, not per-symbol names) and validates, against real v3.0 crypto: a
  populated `C_GetInterfaceList`, an EdDSA sign/verify round trip, an HKDF derive, and a
  message-based AES-GCM round trip. Gated purely behind `#[ignore]`, like every other
  vendor HSM suite (no Cargo feature — `kryoptic` is never a real dependency). Run via
  `mise run test:hsm-kryoptic-conformance`
- Add the `hsm-kryoptic-conformance` entry to the `test-nix` job's matrix in
  `.github/workflows/test_all.yml` (fips only, no hardware/secrets required — does not
  need the concurrency-limited vendor HSM matrix), reusing the same
  `mise run test:<type> --variant <features>` pattern as every other `test-nix` entry
  instead of a standalone job with duplicated scaffolding
  (checkout/cleanup-runner/setup-nix/install-mise)

## Bug Fixes (Testing)

- Fix the Kryoptic conformance CI entry failing on runners with an older system OpenSSL
  (e.g. Ubuntu 22.04/24.04 ship 3.0.x): `kryoptic`'s `standard` feature requires OpenSSL
  >= 3.2.0 via `ossl/dynamic`'s `pkg-config` probe, which picked up whichever OpenSSL
  happened to be installed system-wide. `kryoptic_build_cdylib` now first builds this
  workspace's own OpenSSL 3.6.2 (`crate/crypto/build.rs`, reused if already built) and
  points the probe at it via `PKG_CONFIG_PATH`, uniformizing the OpenSSL version used by
  the conformance suite with the rest of the workspace on every machine, local or CI
- Fix two stale test-vector registrations left over from a `test_data` submodule
  update: `vector_runner.rs` still called `test_vec_hsm_resident_ec_p256_rejected`/
  `..._ec_p384_rejected`, pointing at
  `test_data/vectors/hsm/resident_ec_p{256,384}_rejected`, directories that no longer
  exist — they were renamed upstream to `resident_ec_p{256,384}_created` when HSM
  EC keypair creation became supported (PR hsm_delegation), which made the CI job
  fail with `Cannot read test vector manifest ... No such file or directory`. Renamed
  the tests to `test_vec_hsm_resident_ec_p{256,384}_created`, moved them out of the
  "Negative tests" section (they no longer expect rejection) next to
  `resident_rsa4096_create_sign`, and updated `README.md`'s vector table accordingly

## Documentation

- Document the new v3.0 mechanisms and the Kryoptic conformance suite in
  `documentation/docs/hsm_support/hsm_operations.md`
- Amend ADR-2026-09-03 recording that native v3.0 mechanism wiring and a concrete
  conformance oracle (Kryoptic) have landed, and that Craton HSM
  (`craton-co/craton-hsm-core`) was evaluated and rejected as a conformance oracle for
  now (too immature: ~5 months old, small maintainer group, no independent security
  review)

---

KMIP-level reachability remains RSA-only (`SignatureVerify`); EdDSA/HKDF/message-AEAD
are implemented and tested at the `base_hsm` layer but not yet reachable through a KMIP
operation end-to-end, pending a `KeyType`/`HsmKeypairAlgorithm` enum expansion — tracked
separately in [#1182](https://github.com/Cosmian/kms/issues/1182).

# PKCS#11 v3 interfaces discovery, `C_LoginUser`, and conformance profiles

## Features

### HSM

- Implement the Cryptoki v3.0 "interfaces" discovery entry points, `C_GetInterfaceList` and
  `C_GetInterface`, in the `cosmian_pkcs11` provider library, in addition to the existing
  `C_GetFunctionList`. Purely additive: v2.40-only consumers keep working unchanged
  ([#1153](https://github.com/Cosmian/kms/issues/1153))
- Implement `C_LoginUser` (previously unimplemented): behaves like `C_Login`, since the
  library exposes a single implicit backend identity
- Wire up the pre-existing `Object::Profile`/`CKO_PROFILE` mechanism so the library
  self-declares its OASIS PKCS#11 v3.0 conformance profiles (`CKP_BASELINE_PROVIDER`,
  `CKP_EXTENDED_PROVIDER`, `CKP_AUTHENTICATION_TOKEN`, `CKP_PUBLIC_CERTIFICATES_TOKEN`) as
  discoverable, public (`CKA_PRIVATE = CK_FALSE`) objects via `C_FindObjects`
- Add stable, namespaced `CKA_UNIQUE_ID` values to provider objects and support exact
  `CKA_PROFILE_ID` filtering for profile discovery, with or without an explicit
  `CKA_CLASS = CKO_PROFILE` filter
- Add the 21 v3.0-only stub entry points required for a non-null `CK_FUNCTION_LIST_3_0`
  (`C_SessionCancel` and the message-based bulk encrypt/decrypt/sign/verify family), all
  returning `CKR_FUNCTION_NOT_SUPPORTED`

## Bug Fixes

### HSM

- Fix `CKA_PRIVATE` on `CKO_PROFILE` objects, previously hardcoded to `CK_TRUE`: per the
  OASIS spec, profile objects must be discoverable pre-login so a client can determine
  supported profiles before authenticating
- Require exact interface version 3.1, validate `C_GetFunctionList` output pointers, and
  preserve authenticated backend state during interface discovery
- Validate `C_Login`/`C_LoginUser` user types and return the standard errors for unsupported
  SO and context-specific logins
- Prevent writes through undersized `C_GetAttributeValue` output buffers, report the required
  size with `CKR_BUFFER_TOO_SMALL`, and enforce token-managed `CKA_UNIQUE_ID` values as read-only

## Documentation

- Add `documentation/docs/integrations/pkcs11_provider.md` documenting the provider
  library's Cryptoki version, interfaces discovery, conformance profiles, and supported
  mechanisms

## Tests

- Add integration tests covering `C_GetInterfaceList`/`C_GetInterface` (including
  mismatched name/version/flags rejection), `C_LoginUser`, and `CKO_PROFILE`
  self-declaration

---

Addresses gaps identified in
[#1153 (comment)](https://github.com/Cosmian/kms/issues/1153#issuecomment-5539153215)

# PKCS#11 v3.0 scope decision & FFI foundation

## Features

### HSM

- Add an additive, read-only PKCS#11 v3.0 capability probe to `HsmLib`
  (`supports_pkcs11_v3_interfaces`, `list_pkcs11_v3_interfaces`): detects whether the
  loaded PKCS#11 library exposes the v3.0 interfaces discovery entry point
  (`C_GetInterfaceList`) without changing how any Cryptoki function is resolved or
  called. v2.40-only libraries (SoftHSM2, Utimaco, Proteccio, Crypt2Pay, SmartCard HSM)
  are unaffected and report "not supported" ([#1153](https://github.com/Cosmian/kms/issues/1153))

## Documentation

- Document PKCS#11 protocol version compatibility and the new capability probe in
  `documentation/docs/hsm_support/hsm_operations.md`
- Add ADR-2026-09-03 recording the PKCS#11 v3.0 scope decision: use the canonical v3 ABI
  types already provided by `pkcs11-sys` instead of forking it

---

Closes #1153
