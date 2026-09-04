# PKCS#11 provider module

The Eviden KMS ships a PKCS#11 v3.0 provider library, `libcosmian_pkcs11` (`.so` on Linux, `.dylib`
on macOS, `.dll` on Windows), which exposes KMS-managed keys as a Cryptoki token to any PKCS#11-aware
application.

This page documents capabilities of the provider library itself. It is shared by every integration
that loads the library, including [Veracrypt](disk_encryption/veracrypt.md),
[LUKS](disk_encryption/luks.md), [Cryhod](disk_encryption/cryhod.md),
[Oracle Database TDE](databases/oracle_tde.md), and [OpenSSH](openssh.md). See those pages for
integration-specific setup steps.

## Cryptoki version and interfaces discovery

The library implements the Cryptoki v2.40 function list (`C_GetFunctionList`) and additionally
implements the Cryptoki v3.0 "interfaces" discovery entry points, `C_GetInterfaceList` and
`C_GetInterface` (`CK_INFO.cryptokiVersion` is reported as 3.1).

This is purely **additive**: every consumer that only knows about `C_GetFunctionList` (Cryptoki
v2.40 style, the previous behavior of this library) keeps working unchanged. A v3.0-aware consumer
may instead discover the library's single "PKCS 11" interface via `C_GetInterfaceList`/
`C_GetInterface` and obtain the exact same v2.x function pointers plus a small set of v3.0-only
entry points.

- `C_GetInterfaceList(NULL, &count)` reports `count = 1` (the library exposes a single interface).
- `C_GetInterface(NULL, NULL, &pInterface, 0)` returns that interface unconditionally; a caller may
  instead pass the explicit name `"PKCS 11"` and/or an explicit major version (only major version 3
  is matched) — any other name, an unsupported major version, or non-zero `flags` is rejected with
  `CKR_ARGUMENTS_BAD`.
- v3.0-only functions that this library does not natively implement (`C_LoginUser`,
  `C_SessionCancel`, and the message-based bulk encrypt/decrypt/sign/verify family —
  `C_Message*Init`/`C_*MessageBegin`/`C_*MessageNext`/`C_Message*Final`) are present in the v3.0
  function list as required by the specification (a v3.0 function list must not contain null
  pointers), but return `CKR_FUNCTION_NOT_SUPPORTED` when called. Applications that need those
  specific operations should continue to use the equivalent v2.x calls
  (`C_Encrypt`/`C_Decrypt`/`C_Sign`/`C_Verify`), which are fully implemented.

## Supported mechanisms

| Mechanism | Purpose | Notes |
|-----------|---------|-------|
| `CKM_AES_KEY_GEN` | AES key generation | Generates AES-256 keys |
| `CKM_AES_CBC`, `CKM_AES_CBC_PAD` | AES-CBC encryption/decryption | — |
| `CKM_AES_GCM` | AES-GCM authenticated encryption/decryption | See below |
| `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS` | RSA encryption and RSA-PSS signing | — |
| `CKM_ECDSA` | ECDSA signing | — |
| `CKM_EDDSA` | EdDSA (Ed25519) signing | Cryptoki v3.0 mechanism, already supported |

### `CKM_AES_GCM`

`CKM_AES_GCM` performs AES-GCM authenticated encryption/decryption through the KMS, using the
`CK_GCM_PARAMS` structure to carry the initialization vector (IV), optional additional
authenticated data (AAD), and tag length:

- `pIv`/`ulIvLen`: IV, 1 to 128 bytes (a 12-byte/96-bit IV is the recommended default).
- `pAAD`/`ulAADLen`: optional AAD, 0 to 1 MiB (`pAAD` may be `NULL` when `ulAADLen` is 0).
- `ulTagBits`: must be exactly `128` — the KMS's AES-GCM backend always produces/verifies a
  128-bit (16-byte) authentication tag; any other value is rejected with `CKR_MECHANISM_INVALID`.

`C_Encrypt` returns `ciphertext || tag` (the 16-byte tag appended after the ciphertext), and
`C_Decrypt` expects that same `ciphertext || tag` layout as input — this matches the convention
used by OpenSSL's and most other PKCS#11 AES-GCM implementations.

```c
CK_BYTE iv[12] = { /* random IV */ };
CK_BYTE aad[]  = "context-binding-data";
CK_GCM_PARAMS gcm_params = {
    .pIv = iv, .ulIvLen = sizeof(iv), .ulIvBits = 0,
    .pAAD = aad, .ulAADLen = sizeof(aad) - 1,
    .ulTagBits = 128,
};
CK_MECHANISM mechanism = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };

C_EncryptInit(session, &mechanism, key_handle);
/* ciphertext buffer must be at least plaintext_len + 16 bytes (for the appended tag) */
C_Encrypt(session, plaintext, plaintext_len, ciphertext, &ciphertext_len);
```

## Backward compatibility

No configuration change and no code change are required to keep using the PKCS#11 provider library
as before: existing v2.40-only consumers keep calling `C_GetFunctionList` exactly as they always
have, and every previously-supported mechanism (`CKM_AES_CBC`, `CKM_RSA_PKCS`, `CKM_ECDSA`,
`CKM_EDDSA`, etc.) is unchanged. `CKM_AES_GCM` and the v3.0 interfaces discovery entry points are
new, optional capabilities.

## Logging

The PKCS#11 module logs to the `cosmian-pkcs11.log` file in the `.cosmian` subdirectory of the
configuration file. The `COSMIAN_PKCS11_LOGGING_LEVEL` environment variable controls the logging
level (`trace`, `debug`, `info`, `warn`, or `error`; defaults to `info`).
