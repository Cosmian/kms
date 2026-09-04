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
- Add ADR-2026-09-03 recording the PKCS#11 v3.0 scope decision (FFI approach: hand-write
  the minimal v3.0 interfaces surface instead of forking `pkcs11-sys`)

---

Closes #1153
