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
