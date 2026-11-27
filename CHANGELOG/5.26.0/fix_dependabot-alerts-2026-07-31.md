## Fix Dependabot security alerts (2026-07-31)

**Security fixes** — resolves 8 of 9 open Dependabot alerts.

### Rust dependencies

- Upgraded `cosmian_logger` 0.7 → 0.8, removing the vulnerable `opentelemetry_sdk` 0.29.0 (#87).
- Added `postcss` override (`>=8.5.18`) to force transitive upgrade from 8.5.15 (#95).
- `scratchstack-aws-signature` remains pinned at 0.10 — the 0.11 major API redesign (tower Service trait) requires non-trivial migration. The transitive `ring` 0.16.20 alert (#47) has CVSS 0 (informational; applies only in debug overflow-checking mode) and has **zero practical impact** in release builds.

### UI dependencies

- Upgraded `react-router-dom` 7.15.0 → 7.18.2 (#90, #92, #93, #94).
- Note: #91 (react-router RSC CSRF bypass) requires v8.3.0 and is **not applicable** — the KMS Web UI does not use React Server Components (RSC).
- Updated `js-yaml` override `>=4.3.0` → `>=5.2.2` (#96).
- Added `postcss` override `>=8.5.18` to force upgrade the transitive dependency (#95).

### Code changes

- Fixed `cosmian_logger` 0.8 API change: removed the removed `full` feature from `crate/server/Cargo.toml` dependency.
- Fixed `error!` macro import conflict in `crate/clients/pkcs11/provider/src/lib.rs` — `cosmian_logger` 0.8 exports a public `error` module that collides with the local `mod error;`. Changed to explicit `cosmian_logger::error!` calls.
