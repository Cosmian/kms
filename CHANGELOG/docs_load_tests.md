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

### 🐛 Bug Fixes

- **SQLite**: Enable WAL journal mode, `synchronous=NORMAL`, and `busy_timeout=5000` on connection
  open to fix a ~4× key-creation throughput regression (10 ms → sub-ms per write) observed in
  Docker/overlayfs environments where fsync latency is high.
