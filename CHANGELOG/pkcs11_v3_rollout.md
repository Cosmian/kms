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

---

Closes #1156
