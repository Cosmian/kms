# 5.21.0 release notes (full text)

Full text of the `## [5.21.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.21.0] - 2026-04-21

### 🚀 Features

#### PKCS#11 Enhancements

- **`cosmian_pkcs11_verify` diagnostic binary**: new standalone tool that dynamically loads `libcosmian_pkcs11.so` via the standard PKCS#11 C API and validates `ckms.toml` loading and KMS server reachability; enumerates all supported object classes with per-class counts; supports OIDC/JWT bearer-token auth via `--token <JWT>` or `COSMIAN_PKCS11_TOKEN` env var
- **Oracle TDE wallet migration support**: remove `CKF_WRITE_PROTECTED` from token flags; add `CKM_AES_KEY_GEN`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD` to the supported mechanism list; enables both forward (software → HSM) and reverse (HSM → software) wallet migrations
- **Standalone PKCS#11 ZIP package**: `cosmian_pkcs11_verify`, `libcosmian_pkcs11.{so,dylib}`, and signing key bundled in a signed cross-platform ZIP and published to `package.cosmian.com`

#### Web UI

- **Formalised connection states**: the UI now explicitly handles five states — DEV unrestricted mode, no KMS server reachable, server with no auth, mTLS (certificate) auth, and JWT/OIDC auth (including combined JWT+mTLS)
- **No-auth warning banner**: displays a clear banner when the KMS is started without authentication
- **mTLS login page**: shows a clear error when no valid client certificate is provided, instead of silently looping

### 🔒 Security

- **EXT2-1/A04-1**: Reduce HTTP payload size limit from 10 GB to 64 MB (`PayloadConfig` and `JsonConfig`) to prevent memory exhaustion DoS
- **EXT2-2/A03-2**: Add recursion depth limit (`MAX_TTLV_DEPTH = 64`) to TTLV binary parser to prevent stack-overflow DoS via deeply-nested structures
- **EXT2-3/A03-3**: Add stack-depth limit (`MAX_XML_STACK_DEPTH = 64`) to TTLV XML deserializer to prevent DoS via deeply-nested XML
- **EXT2-4/A04-3**: Add `MAX_LOCATE_ITEMS = 1000` server-side cap in `locate.rs`; effective limit is `min(client_requested_max, 1000)`
- **EXT2-5/A04-2**: Add rate-limiting middleware (`actix-governor`) controlled by `KMS_RATE_LIMIT_PER_SECOND` / `rate_limit_per_second`; disabled by default
- **EXT1-1**: Change `derive_pbkdf2` and `derive_hkdf` return types to `Zeroizing<Vec<u8>>` so derived key bytes are scrubbed from memory on drop
- **TTLV OOM guard**: Add `MAX_TTLV_FIELD_BYTES = 64 MiB` per-field length guard to `TTLVBytesDeserializer`; `ByteString`, `TextString`, and `BigInteger` reject oversized length claims before any allocation
- **A01-1/A05-1**: Replace `Cors::permissive()` on the main KMIP scope with `Cors::default()` restricted to `cors_allowed_origins`; add `cors_allowed_origins` config field (env `KMS_CORS_ALLOWED_ORIGINS`)
- **A07-1**: Reject symmetric JWT algorithms (HS256/HS384/HS512) via an explicit asymmetric-only allowlist; explicitly pin `validation.algorithms` to prevent confusion attacks
- **A07-2**: Replace plain `==` API-token comparison with constant-time `subtle::ConstantTimeEq` to eliminate timing side-channel
- **A07-4**: Change session cookie `SameSite` attribute from `None` to `Strict` to prevent CSRF attacks
- **A07-5**: Add `validate_jwks_uris_are_https()` startup guard; any non-HTTPS JWKS URI causes the server to refuse to start (gated behind `#[cfg(not(feature = "insecure"))]`)
- **A08-2**: Emit a startup `warn!` when `ui_session_salt` is not configured
- **A09-1**: Mask database URL passwords in `MainDBConfig::Display` using a URL-parser-based `mask_db_url_password()` helper
- **A09-2**: Replace dot-only TLS P12 password masking with a proper `[****]` redaction
- **A09-3**: Change `debug!` to `warn!` for all 401-unauthorized paths in `jwt_token_auth.rs`
- **A10-2/A10-3**: Build `reqwest` HTTP client with `redirect::Policy::none()` in the JWKS fetcher and UI OAuth token exchange to prevent SSRF via crafted redirects
- **SSDF PW.5.1**: Add `[[bans.features]]` entry in `deny.toml` banning `serde_json::unbounded_depth`

### 🐛 Bug Fixes

#### Server / Auth

- **Stale session cookie warnings**: session cookie key is now derived deterministically from the public URL instead of being regenerated randomly each start; configure `ui_session_salt` for multi-instance deployments
- **Header crash on partial server-info response**: guard `serverInfo?.hsm` before accessing `hsm.configured`

#### Web UI

- **E2E test race condition**: fixed non-deterministic sitemap test failures caused by the initial render briefly showing the error page before auth resolved
- **Dev setup login crash**: fixed a crash in the dev setup OAuth flow despite valid credentials
- **OAuth/OIDC**: multiple fixes to the OAuth interface, mostly dev-only scenarios; removed misleading "JWT is enabled" message

#### Logging / Startup

- **`HttpConfig::Display`**: no longer hardcodes `http://`; a new `scheme()` helper returns the correct scheme based on TLS config; `ClapConfig::Debug` now logs the correct `https://` or `http://` URL

### 📚 Documentation

#### Oracle TDE / PKCS#11

- Rewrite Mode 1 and Mode 2 architecture diagrams (Mermaid); expand "HSM Identity and Authentication" section clarifying `libcosmian_pkcs11.so` proxy role; add environment variable reference table; add "OIDC / JWT Keystore Authentication" section; add "Wallet Migration" section covering forward and reverse migrations

#### Web UI

- **`configuration/ui.md`**: document the five UI connection states and the Certificate Authentication (mTLS) setup

### 🧪 Testing

- **PKCS#11**: add integration tests `test_pkcs11_oidc_login_full_sequence`, `test_pkcs11_migrate_software_to_hsm`, and `test_pkcs11_reverse_migrate_hsm_to_software` (non-fips)
- **KMIP wire edge cases**: 25 binary wire tests (W1–W25), 3 TTLV OOM-guard tests (W26–W28), and 18 XML edge-case tests (X1–X18)
- **Security regression tests**: JWT algorithm allowlist (A1–A6), CORS no-wildcard policy (C1–C3), privilege bypass (PB1–PB4), KMIP batch abuse (B1–B5), JWKS SSRF (SR1–SR2), DB URL masking (N1–N5), JWKS HTTPS startup guard (J1–J4)
- **CLI adversarial payloads**: 15 wire-payload tests (S1–S15) — empty, truncated, garbage, deeply-nested TTLV, malformed JSON, 1 MB random binary
- **HSM**: fix flaky SIGSEGV in `test_hsm_*_all` by sharing a single `BaseHsm` and `Arc<SlotManager>` instance per test run instead of repeated `C_Initialize`/`C_Finalize`/`dlopen`/`dlclose` cycles

### 🔄 Refactor

- Move CLI crates to `crate/clients/` subdirectory; flatten `kms/` subdirectory under actions and tests; rename `cosmian_kms_cli` → `cosmian_kms_cli_actions`

### 🔧 CI

- **Automated release workflow** (`release.yml`): new `workflow_dispatch` workflow that fully automates the release flow — creates the `release/<version>` branch, bumps all versions via `release.sh --ci`, regenerates the CBOM, updates Nix vendor hashes, triggers packaging, retrieves SBOMs, pushes the annotated tag, and performs git-flow finalisation
- **PKCS#11 build fix**: add explicit `cargo build -p cosmian_pkcs11 --features non-fips` step before workspace lib tests in `main_base.yml`, `cargo_test.ps1`, and `common.sh` so `libcosmian_pkcs11.{so,dylib,dll}` exists at test time
- **Oracle TDE CI**: fix migration test order (reverse before forward), handle `ORA-28354` (wallet already open) as non-fatal, remove `WITH BACKUP` from SW→HSM migration to avoid `ORA-46623`
- **Pin pnpm to `10.17.1`** across all CI environments (`ui/package.json`, `test_ui.sh`, `build_ui.sh`, `test_wasm.sh`, `test_windows.yml`) to prevent `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`
- **Windows `test_ui.ps1`**: fix KMS log file paths, add `--frozen-lockfile` to `pnpm install`, fix PowerShell 7+ readiness check (`Invoke-WebRequest` exception handling)
- **`pkcs11-zip`** added to default Linux package types in `nix.sh` so ZIP artifacts are built and published correctly
- Update macOS Nix CLI vendor hash files (`cli.vendor.*.darwin.sha256`) after PKCS#11 loader dependency additions
