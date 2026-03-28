# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### 🚀 Features

- **UI**: Add DeriveKey page — derive a symmetric key from an existing key or password using PBKDF2/HKDF, with full WASM binding (`derive_key_ttlv_request`, `parse_derive_key_ttlv_response`).
- **UI**: Add `/server-info` endpoint exposing KMS version, FIPS mode, and HSM status; display HSM info in the UI header.
- **UI**: Add `--no-ui` / `KMS_UI_ENABLE=false` server flag to disable the built-in web interface at runtime.
- **UI**: Regroup Azure, AWS, and Google CSE menu entries under a "Hyperscalers" group; add icons to all sidebar categories.
- **UI**: Hide PQC, MAC, and Covercrypt menu entries when the server is running in FIPS mode.
- **Benchmarks**: Generate self-contained HTML benchmark reports (gnuplot SVGs) alongside existing Markdown outputs.
- **SBOM**: Generate Software Bill of Materials for the `ckms` CLI binary in `sbom/ckms/` (all 4 variant × link-type combinations).

### 🚜 Refactor

- **ckms**: Renamed TLS-related CLI parameters and environment variables from `ssl_xxx` to `tls_xxx` (e.g. `--ssl-client-pkcs12-path` → `--tls-client-pkcs12-path`, `KMS_SSL_CLIENT_PKCS12_PATH` → `KMS_TLS_CLIENT_PKCS12_PATH`). Update any scripts or config files that reference the old `ssl_` prefix.

### 🐛 Bug Fixes

- **CI**: DB-backed test scripts now fail fast when required services are unreachable instead of silently succeeding after skipping that backend, so `bash .github/scripts/nix.sh --variant non-fips test psql` correctly returns a non-zero exit code when PostgreSQL is down.
- **SQLite**: Enable WAL journal mode, `synchronous=NORMAL`, and `busy_timeout=5000` on connection
  open to fix a ~4× key-creation throughput regression (10 ms → sub-ms per write) observed in
  Docker/overlayfs environments where fsync latency is high.
- **CI**: All test scripts that start the KMS server are now protected against a system-level `/etc/cosmian/kms.toml`; `test_hsm_softhsm2.sh`, `test_hsm_utimaco.sh`, and `test_hsm_proteccio.sh` write a temporary config file and pass `--config` explicitly so the server never falls back to the default path. `common.sh` now warns early when the default config file is found on the host. ([#810](https://github.com/Cosmian/kms/issues/810))
