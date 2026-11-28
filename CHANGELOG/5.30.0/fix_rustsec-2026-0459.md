## Bug Fixes

### Dependencies

- Fix RUSTSEC-2026-0459 (CVE-2026-119375, bundled SQLite < 3.54 may return uninitialised page-cache memory): upgrade `rusqlite` 0.37 → 0.41 (`libsqlite3-sys` 0.35 → 0.39.1) and replace `tokio-rusqlite` with a small in-house async connection wrapper in `crate/server_database/src/stores/sql/sqlite.rs`; remove the advisory ignores from `deny.toml` and `.cargo/audit.toml`
