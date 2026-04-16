# cosmian_pkcs11_verify

Diagnostic binary that dynamically loads `libcosmian_pkcs11.so` (or `.dylib` / `.dll`) and
walks through the standard PKCS#11 C API sequence to verify that:

- the shared library opens without error,
- `ckms.toml` is found and parsed correctly (validated by `C_GetFunctionList`),
- the Cosmian KMS server declared in `ckms.toml` is reachable (validated when `C_FindObjects`
  performs the first REST call).

This binary has **no dependency on the `cosmian_pkcs11` crate** — it exercises the library
purely through the C PKCS#11 ABI using `libloading` and `pkcs11-sys`.

---

## Usage

```shell
cosmian_pkcs11_verify --so-path <PATH> [--conf <PATH>]
```

| Flag | Env var | Description |
|------|---------|-------------|
| `--so-path <PATH>` | `COSMIAN_PKCS11_LIB` | Path to the PKCS#11 shared library |
| `--conf <PATH>` | — | Explicit path to `ckms.toml`; sets `CKMS_CONF` before loading |

### Examples

```bash
# Default ckms.toml at ~/.cosmian/ckms.toml
cosmian_pkcs11_verify --so-path /usr/local/lib/libcosmian_pkcs11.so

# Explicit config
cosmian_pkcs11_verify \
  --so-path /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so \
  --conf /home/oracle/.cosmian/ckms.toml

# Increase log verbosity from the library side
COSMIAN_PKCS11_LOGGING_LEVEL=debug \
  cosmian_pkcs11_verify --so-path /usr/local/lib/libcosmian_pkcs11.so
```

### Expected output (success)

```text
[conf] Will use default home config: /home/oracle/.cosmian/ckms.toml

[load] Opening: /usr/local/lib/libcosmian_pkcs11.so
[load] OK: shared library opened

[C_GetFunctionList] OK: ckms.toml parsed and KmsClient instantiated
[C_Initialize] OK
[C_GetSlotList] OK: using slot ID 1
[C_OpenSession] OK: session opened on slot 1
[C_FindObjects] Enumerating objects by class:
  CKO_DATA: N
  CKO_PUBLIC_KEY: N
  CKO_PRIVATE_KEY: N
  CKO_SECRET_KEY: N
[C_FindObjects] OK: N PKCS#11 object(s) visible on KMS
[C_CloseSession] OK
[C_Finalize] OK

All checks passed.
```

Non-zero exit code means a step failed; a human-readable error message with the `CKR_*`
constant name and a contextual hint is printed to stderr.

---

## Validation steps

| Step | PKCS#11 call | What it validates |
|------|-------------|-------------------|
| A | (pre-flight) | Prints which `ckms.toml` will be used |
| B | `Library::new()` | `.so` / `.dylib` / `.dll` is loadable |
| C | `C_GetFunctionList` | Config found + parsed; `KmsClient` struct created |
| D | `C_Initialize` | Module initializes |
| E | `C_GetSlotList` | Slot enumerated (SLOT_ID=1) |
| F | `C_OpenSession` | Session created |
| G–I | `C_FindObjects{Init,…,Final}` | KMS REST calls for each class (CKO_DATA, CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY); prints per-class and total count |
| J | `C_CloseSession` | Clean session teardown |
| K | `C_Finalize` | Module finalizes |

---

## Environment variables

See the [Environment Variables Used by `libcosmian_pkcs11`](../../../../../../../documentation/docs/integrations/databases/oracle_tde.md#environment-variables-used-by-libcosmian_pkcs11)
table in the Oracle TDE integration guide for the full list of variables consumed by the
library itself (`COSMIAN_PKCS11_LOGGING_LEVEL`, `COSMIAN_PKCS11_LOGGING_FOLDER`,
`COSMIAN_PKCS11_DISK_ENCRYPTION_TAG`, `COSMIAN_PKCS11_SSH_KEY_TAG`,
`COSMIAN_PKCS11_IGNORE_SESSIONS`).

---

## Further reading

Full Oracle TDE integration guide (canonical documentation):
[documentation/docs/integrations/databases/oracle_tde.md](../../../../../../../documentation/docs/integrations/databases/oracle_tde.md)

Online: <https://docs.cosmian.com/integrations/databases/oracle_tde/>
