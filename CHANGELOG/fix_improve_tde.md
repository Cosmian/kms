## Features

### PKCS#11

- Add `cosmian_pkcs11_verify` diagnostic binary (`crate/clients/pkcs11/loader`) that dynamically loads `libcosmian_pkcs11.so` via `libloading` and validates `ckms.toml` loading and KMS server reachability through the standard PKCS#11 C API (`C_GetFunctionList` → `C_Initialize` → `C_GetSlotList` → `C_OpenSession` → `C_FindObjects` per class → `C_Finalize`)
- Fix `cosmian_pkcs11_verify` to iterate `C_FindObjects` in a pagination loop (PKCS#11 §5.13) instead of capping at 64 handles — all matching objects are now counted correctly
- Fix `cosmian_pkcs11_verify` to enumerate all supported PKCS#11 object classes (`CKO_DATA`, `CKO_CERTIFICATE`, `CKO_PUBLIC_KEY`, `CKO_PRIVATE_KEY`, `CKO_SECRET_KEY`) with per-class counts and a grand total; per-class errors (e.g. `CKO_CERTIFICATE` failing due to a provider limitation) are non-fatal and reported inline
- Ship `cosmian_pkcs11_verify` in the `cosmian_pkcs11` provider standalone package (deb/rpm, all variants: static/dynamic × fips/non-fips) alongside `libcosmian_pkcs11.so`, as well as in the `ckms` full package and Windows/macOS installers
- Replace standalone `cosmian_pkcs11` deb/rpm packaging with a signed cross-platform **ZIP archive** (`cosmian-pkcs11-<variant>-<link-suffix>_<version>_<os>-<arch>.zip`) containing `libcosmian_pkcs11.{so,dylib}`, `cosmian_pkcs11_verify`, and the public signing key; ZIP is built by `.github/scripts/package/package_pkcs11_zip.sh`, signed with GPG, and published to `package.cosmian.com` via the `pkcs11-zip` package type in the CI matrix
- Add OIDC/JWT bearer-token authentication mode for `cosmian_pkcs11_verify`: passing `--token <JWT>` causes a `C_Login(CKU_USER, pin=<JWT>)` call after `C_OpenSession`, enabling verification of KMS servers configured with `pkcs11_use_pin_as_access_token = true`; the token may also be supplied via the `COSMIAN_PKCS11_TOKEN` environment variable

## Testing

### PKCS#11

- Split `cosmian_pkcs11_verify` crate into `[lib]` + `[[bin]]` targets so that integration tests in `src/tests.rs` are discoverable by `cargo test --lib --workspace` (as used by `cargo test-non-fips`); all shared helper functions moved to `src/lib.rs` as `pub` items, binary entry point kept in `src/main.rs`
- Add integration test `test_pkcs11_oidc_login_full_sequence` (feature-gated behind `non-fips`) exercising the full PKCS#11 sequence with OIDC/JWT authentication: starts an in-process KMS test server with JWT auth, dynamically loads `libcosmian_pkcs11.so`, calls `C_Login` with a real Auth0 token, and verifies that `C_FindObjects` enumerates KMS objects correctly

## Documentation

### Oracle TDE

- Rewrite Mode 1 and Mode 2 architecture diagrams: remove `**bold**` syntax (not supported by MkDocs mermaid renderer), and add an outer "Oracle Database Server" subgraph in Mode 2 to make clear that `libcosmian_pkcs11.so` resides on the Oracle host
- Expand "HSM Identity and Authentication" section: clarify that `libcosmian_pkcs11.so` is a proxy between Oracle and the KMS server (not an HSM driver), that the KMS server owns the HSM connection (slot + PIN), that `hsm_identity_pass` is NOT the HSM PIN but a mandatory SQL placeholder required by Oracle's `IDENTIFIED BY` syntax, and that authentication to the KMS is via TLS/mTLS configured in `ckms.toml`
- Add "Environment Variables Used by `libcosmian_pkcs11`" reference table covering `CKMS_CONF`, `COSMIAN_PKCS11_LOGGING_LEVEL`, `COSMIAN_PKCS11_LOGGING_FOLDER`, `COSMIAN_PKCS11_DISK_ENCRYPTION_TAG`, `COSMIAN_PKCS11_SSH_KEY_TAG`, `COSMIAN_PKCS11_IGNORE_SESSIONS`, with usage notes and a `cosmian_pkcs11_verify` quick-check example
- Add "OIDC / JWT Keystore Authentication (Dynamic Token)" section documenting mode 2 (`pkcs11_use_pin_as_access_token = true`): three-mode comparison table (no auth / static token / OIDC dynamic), `ckms.toml` config, Oracle SQL example, wrapper script pattern, security properties, and `cosmian_pkcs11_verify --token` verification
- Add "Verifying the library loads correctly" subsection with per-mode usage examples for `cosmian_pkcs11_verify` including `--token` for mode 2 and the expected output format for each scenario
