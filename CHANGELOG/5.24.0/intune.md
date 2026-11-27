## Bug Fixes

### CNG KSP — `ckms cng register` is now idempotent

`BCryptRegisterProvider` returns `STATUS_OBJECT_NAME_COLLISION` (`0xC0000035`) when
the provider is already registered. The register command now treats this NTSTATUS as
success instead of an error, so running `ckms cng register` a second time (or after
an NSIS installer has already registered the DLL) no longer aborts with:

```text
ERROR: BCryptRegisterProvider failed with NTSTATUS 0xc0000035
```

**Files changed**: `crate/clients/cng/src/registry.rs`, `crate/clients/clap/src/actions/cng.rs`

### CNG KSP — BCrypt blob magic constants corrected (Intune connector incompatibility)

Six `BCRYPT_*_MAGIC` constants in `crate/clients/cng/src/blob.rs` had their bytes scrambled,
causing the exported RSA public-key blob to begin with `"RAS1"` instead of the required `"RSA1"`
(`BCRYPT_RSAPUBLIC_BLOB`). The Intune Java connector rejects any blob whose first four bytes are
not exactly `RSA1`, producing:

```text
java.lang.IllegalArgumentException: Key is not a RSA key of BCrypt format
```

Similarly, the ECDSA P-256/P-384/P-521 constants mapped to `"ES61/63/65"` instead of `"ECS1/3/5"`.

**Root cause**: hex literals were written as big-endian representations of the mnemonic string
instead of as the little-endian `u32` value that `to_le_bytes()` emits.

| Name | Wrong | Correct | Bytes (LE) |
|------|-------|---------|------------|
| `BCRYPT_RSAPUBLIC_MAGIC` | `0x3153_4152` | `0x3141_5352` | `RSA1` |
| `BCRYPT_RSAPRIVATE_MAGIC` | `0x3253_4152` | `0x3241_5352` | `RSA2` |
| `BCRYPT_RSAFULLPRIVATE_MAGIC` | `0x3352_5341` | `0x3341_5352` | `RSA3` |
| `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` | `0x3136_5345` | `0x3153_4345` | `ECS1` |
| `BCRYPT_ECDSA_PUBLIC_P384_MAGIC` | `0x3336_5345` | `0x3353_4345` | `ECS3` |
| `BCRYPT_ECDSA_PUBLIC_P521_MAGIC` | `0x3536_5345` | `0x3553_4345` | `ECS5` |

Also fixed the same wrong local constants in `crate/clients/clap/src/actions/cng_verify.rs`
and hardened the PS1 test to assert the exported blob starts with `"RSA1"` and to test
`Export-IntunePublicKey -FileFormat PEM`.

### CI — `test_cng_ksp.ps1` runs under Windows PowerShell 5.1

The `IntunePfxImport` PowerShell module uses `System.Security.AccessControl.CryptoKeySecurity`
from `mscorlib`, a .NET Framework 4.x type absent in .NET 6+ (PowerShell 7). When `test_cng_ksp.ps1`
was invoked via `pwsh.exe` (PowerShell 7), `Add-IntuneKspKey` failed with:

```text
Could not load type 'System.Security.AccessControl.CryptoKeySecurity' from assembly 'mscorlib'
```

Added a self-re-launch block at the top of the script: when PowerShell 6+ is detected the script
transparently re-invokes itself under `powershell.exe` (Windows PowerShell 5.1 / .NET Framework).

**Files changed**: `.github/scripts/windows/test_cng_ksp.ps1`

### CI — `cargo fmt` format fixes

Corrected `rustfmt` formatting in `MoveFileExW` extern declarations
(`crate/clients/cng/src/registry.rs`, `crate/clients/clap/src/actions/cng.rs`).

## Features

### CNG KSP

- Fix `test_sign_with_rsa_key`: RSA key pairs now set `activation_date` in `CreateKeyPair`
  `common_attributes` so they are created in `Active` state (keys without an activation date
  were created in `PreActive` state and rejected by the KMS sign operation).
- Fix `test_list_cng_keys`: `GetAttributes` in `list_cng_keys` now explicitly requests the
  vendor tag attribute (`cosmian:tag`) so that `extract_cng_name_from_tags` can resolve the
  CNG key name (the default `attribute_reference: None` excludes the tag vendor attribute).
- Fix feature propagation: add `test_kms_server/non-fips` to the `non-fips` feature of the
  `cosmian_cng` crate so that `cosmian_kms_server_database` is compiled with the
  correct `non-fips` features when running single-crate tests.
- Add `revoke_key` backend function and update all test cleanup to revoke keys before
  destroying them (KMIP requires Active keys to be revoked before destruction).
- Add `cosmian_cng_verify` standalone tool that loads and exercises all CNG KSP
  backend functions (RSA/EC key creation, signing, encryption, key listing, export, and
  lifecycle management).
- Implement `verify_signature` backend function using the KMIP `SignatureVerify` operation,
  enabling RSA PKCS1v15, RSA-PSS, and ECDSA signature verification through the KMS.
- Fix `digital_signature_algorithm` in `sign_hash` and `verify_signature` to explicitly set
  the algorithm (e.g. `SHA256WithRSAEncryption` for PKCS1v15, `RSASSAPSS` for PSS) instead
  of leaving it `None`, which caused the server to default to PSS for all RSA signatures.
- Parse `pv_padding_info` in `sign_hash`, `verify_signature`, `encrypt`, and `decrypt` NCrypt
  functions to honor the hash algorithm and salt length from CNG padding info structs
  (`BCRYPT_PKCS1_PADDING_INFO`, `BCRYPT_PSS_PADDING_INFO`, `BCRYPT_OAEP_PADDING_INFO`).
- Implement `EnumAlgorithms` to return supported algorithms (RSA, ECDSA P-256/P-384/P-521,
  ECDH P-256/P-384/P-521) with operation class filtering.
- Update `delete_key` to revoke both private and public keys before destroying them.
- Add EC P-384 and P-521 key pair creation and signing tests.
- Add RSA-PSS signing, RSA/ECDSA signature verification, and RSA OAEP encrypt/decrypt tests.
- Fix `encrypt` using private key UID instead of public key UID â€" added `pub_uid()` accessor
  to `CngKeyCtx` and updated the encrypt function in `provider.rs` to use it.
- Rewrite `cosmian_cng_verify` to dynamically load the CNG KSP DLL and call exported
  NCrypt functions through the `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`, instead of linking
  directly to the backend module. This verifies the DLL as an external consumer would.

## Documentation

- Replace ASCII text diagrams with Mermaid diagrams in `windows_cng_ksp.md` integration docs.

## CI

- Add `test_cng_ksp.ps1` end-to-end integration test script that builds the CNG KSP DLL,
  starts a local KMS server, registers the KSP, runs the DLL surface verification tool,
  Rust lib tests, and ckms CLI CNG commands.
- Add `test-cng-ksp` job to `test_windows.yml` CI workflow to run the CNG KSP integration
  tests on every PR and push.
- Package `cosmian_cng.dll` and `cosmian_cng_verify.exe` into a ZIP archive
  (`cosmian-cng-non-fips-static-openssl_<version>_windows-x86_64.zip`) built and uploaded
  by the Windows CI pipeline (`build_windows.yml`), mirroring the `cosmian_pkcs11` ZIP
  packaging. The archive is published to `package.cosmian.com` and to GitHub Release assets
  on tagged builds. ([#924](https://github.com/Cosmian/kms/pull/924))

## Refactor

### CNG KSP

- Rename crate `cosmian_kms_cng_ksp` → `cosmian_cng` and `cosmian_kms_cng_ksp_verify` →
  `cosmian_cng_verify`: shorter names, consistent with `cosmian_pkcs11` naming; DLL artifact
  becomes `cosmian_cng.dll` and binary becomes `cosmian_cng_verify.exe`. ([#924](https://github.com/Cosmian/kms/pull/924))
- Move `cosmian_cng_verify` DLL verification logic into `ckms cng verify --dll <path>`;
  remove standalone `cosmian_cng_verify` crate. ([#924](https://github.com/Cosmian/kms/pull/924))
- Move `cosmian_pkcs11_verify` diagnostic logic into `ckms pkcs11 verify --dll <path>`;
  remove standalone `cosmian_pkcs11_verify` crate. ([#924](https://github.com/Cosmian/kms/pull/924))
- Bundle `cosmian_cng.dll` in the ckms NSIS installer (Windows); remove separate CNG ZIP
  archive from CI artifacts. ([#924](https://github.com/Cosmian/kms/pull/924))
- Remove `cosmian_pkcs11_verify` binary from deb/rpm/NSIS packages; the functionality is now
  available via `ckms pkcs11 verify`. ([#924](https://github.com/Cosmian/kms/pull/924))

## Additional Bug Fixes

### CI

- fix(ci): update `test_data` submodule reference from `27a12ab` to `ace8d8d` to include missing CSR test fixtures (`test_rsa2048.csr.pem`, `test_ec_p256.csr.pem`, `test_ed25519.csr.pem`) and HSM config (`hsm_jwt.toml`) that caused compile-time errors across all CI jobs ([#924](https://github.com/Cosmian/kms/pull/924))

### HSM

- fix(hsm): do not forward KMIP PKCS#11 `C_Finalize` to the real HSM library; returning OK without calling `C_Finalize` preserves HSM state and prevents `CKR_DEVICE_REMOVED` (50) on subsequent `C_OpenSession` calls ([#924](https://github.com/Cosmian/kms/pull/924))

### CNG KSP

- Fix `test_locate_key_by_name` non-deterministic failure on Redis-findex: `locate_key_by_name`
  now filters by `ObjectType::PrivateKey` in addition to the CNG name tag, so it no longer
  returns the public key (which shares the same tag) when Redis returns keys in non-deterministic
  order. ([#924](https://github.com/Cosmian/kms/pull/924))

### Testing

- Fix flaky `test_privileged_users` (and other tests using `start_default_test_kms_server_with_privileged_users`) in CI: increase the channel `recv_timeout` from 25 s to 60 s in `start_test_kms_server`, `socket_server`, and `ttlv_tests` to prevent spurious "timed out waiting on channel" failures under CI load. ([#924](https://github.com/Cosmian/kms/pull/924))
- fix(rebase): resolve post-rebase compile errors and test failures by restoring `Activate = 22` in `KmipOperation`, adding `Activate` handling back to `retrieve_object_utils.rs`, preserving `Activate` dispatch and permission checks, removing the duplicate `is_pqc_signature` impl, fixing the `wasm.rs` merge artifact, switching `rekey` dispatch to the `priv` macro variant, and aligning rekey tests with KMIP-compliant new-UID semantics.

### PKCS#11

- refactor(pkcs11): replace hardcoded numeric CKR values in `ckr_name` with a macro referencing
  `pkcs11_sys` constants; covers all 99 standard return codes ([#924](https://github.com/Cosmian/kms/pull/924))

### Logging

- fix(macos): change default rolling log directory from `/Library/Logs/Cosmian KMS Server` (requires root)
  to `~/Library/Logs/Cosmian KMS Server` (user-writable) ([#924](https://github.com/Cosmian/kms/pull/924))

## Testing

- Add `ckms pkcs11 verify` integration tests: build `libcosmian_pkcs11` cdylib before test,
  run against a JWT-authenticated server, and assert failure when no server is running ([#924](https://github.com/Cosmian/kms/pull/924))
