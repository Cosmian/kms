# PKCS#11 provider module

The Eviden KMS ships a PKCS#11 provider library, `libcosmian_pkcs11` (`.so` on Linux, `.dylib`
on macOS, `.dll` on Windows), which exposes KMS-managed keys as a Cryptoki token to any PKCS#11-aware
application.

This page documents capabilities of the provider library itself. It is shared by every integration
that loads the library, including [Veracrypt](disk_encryption/veracrypt.md),
[LUKS](disk_encryption/luks.md), [Cryhod](disk_encryption/cryhod.md),
[Oracle Database TDE](databases/oracle_tde.md), and [OpenSSH](openssh.md). See those pages for
integration-specific setup steps.

## Cryptoki version and interfaces discovery

The library implements the Cryptoki v2.40 function list (`C_GetFunctionList`) and additionally
implements the Cryptoki v3.x "interfaces" discovery entry points, `C_GetInterfaceList` and
`C_GetInterface`.

This is purely **additive**: every consumer that only knows about `C_GetFunctionList` (the previous
behavior of this library) keeps working unchanged. A v3-aware consumer may instead discover the
library's single `"PKCS 11"` interface via `C_GetInterfaceList`/`C_GetInterface` and obtain the same
v2.x function pointers plus a small set of v3-only entry points.

- `C_GetInterfaceList(NULL, &count)` reports `count = 1` (the library exposes a single interface).
- `C_GetInterface(NULL, NULL, &pInterface, 0)` returns that interface unconditionally; a caller may
  instead pass the explicit name `"PKCS 11"` and/or a version. Since this library implements v3.1,
  a version request is accepted when it has major version `3` and minor version `0` or `1`
  (a v3.1 implementation is backward-compatible with v3.0 consumers). Any other name, an
  unsupported version (e.g. `1.x`, `2.x`, or `3.2`), or non-zero `flags` is rejected with
  `CKR_ARGUMENTS_BAD`.
- `C_LoginUser` is implemented: it behaves like `C_Login` (the library exposes a single implicit
  backend identity, so `pUsername`/`ulUsernameLen` are validated as well-formed UTF-8 but otherwise
  ignored). `CKU_USER` is accepted. `CKU_SO` and other unsupported user types return
  `CKR_USER_TYPE_INVALID`, while `CKU_CONTEXT_SPECIFIC` returns `CKR_OPERATION_NOT_INITIALIZED`
  because contextual authentication is not implemented.
- v3 functions that this library does not natively implement (`C_SessionCancel`, and the
  message-based bulk encrypt/decrypt/sign/verify family — `C_Message*Init`/`C_*MessageBegin`/
  `C_*MessageNext`/`C_Message*Final`) are present in the v3.0 function list as required by the
  specification (a v3.0 function list must not contain null pointers), but return
  `CKR_FUNCTION_NOT_SUPPORTED` when called. Applications that need those specific operations should
  continue to use the equivalent v2.x calls (`C_Encrypt`/`C_Decrypt`/`C_Sign`/`C_Verify`), which are
  fully implemented.

## Conformance profiles (`CKO_PROFILE`)

Per the OASIS PKCS#11 v3.1 profiles specification, the library self-declares the conformance
profiles it implements as `CKO_PROFILE` objects, discoverable via `C_FindObjectsInit`/
`C_FindObjects` with a `CKA_CLASS = CKO_PROFILE` template — including on a session that has not
called `C_Login`/`C_LoginUser` yet, since profile objects are public (`CKA_PRIVATE = CK_FALSE`).
Each profile object also has a stable, class-namespaced `CKA_UNIQUE_ID` and can be selected
directly with a `CKA_PROFILE_ID` search template, with or without `CKA_CLASS`.

The library currently declares:

| Profile | `CK_PROFILE_ID` |
|---------|-----------------|
| Baseline Provider | `CKP_BASELINE_PROVIDER` |
| Extended Provider | `CKP_EXTENDED_PROVIDER` |
| Authentication Token | `CKP_AUTHENTICATION_TOKEN` |
| Public Certificates Token | `CKP_PUBLIC_CERTIFICATES_TOKEN` |

`CKP_COMPLETE_PROVIDER` and `CKP_HKDF_TLS_TOKEN` are intentionally not declared, since the
mechanisms they require (key wrap/unwrap, key derivation, and HKDF respectively) are not
implemented by this library.

## Supported mechanisms

| Mechanism | Purpose | Notes |
|-----------|---------|-------|
| `CKM_AES_KEY_GEN` | AES key generation | Generates AES-256 keys |
| `CKM_AES_CBC`, `CKM_AES_CBC_PAD` | AES-CBC encryption/decryption | — |
| `CKM_RSA_PKCS`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS` | RSA PKCS#1 v1.5 signing | — |
| `CKM_RSA_PKCS_PSS` | RSA-PSS signing | — |
| `CKM_ECDSA` | ECDSA signing | — |
| `CKM_EDDSA` | EdDSA signing (Ed25519) | — |

## Backward compatibility

No configuration change and no code change are required to keep using the PKCS#11 provider library
as before: existing v2.40-only consumers keep calling `C_GetFunctionList` exactly as they always
have, and every previously-supported mechanism is unchanged. The v3 interfaces discovery entry
points, `C_LoginUser`, and the self-declared `CKO_PROFILE` objects are new, optional capabilities.

## Logging

The PKCS#11 module logs to the `<log_name>.log` file in the `.cosmian` subdirectory of the
configuration file by default. On Linux, if the `COSMIAN_PKCS11_LOGGING_FOLDER` environment
variable is set, its value is used as the log directory instead. The
`COSMIAN_PKCS11_LOGGING_LEVEL` environment variable controls the logging level (`trace`, `debug`,
`info`, `warn`, or `error`; defaults to `info`).
