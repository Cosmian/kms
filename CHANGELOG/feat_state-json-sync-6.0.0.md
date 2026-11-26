## Bug Fixes

### Database
- Add a 5.30.0 startup migration step (`StoredStateSync`) on SQLite, PostgreSQL, MySQL/MariaDB and Redis with Findex that writes the state clients already see (the lifecycle column; a `PreActive` column defers to the attributes) into the stored attributes and key-block attributes, which can lag the column after `Deactivate`, `Destroy` and `Revoke`; rows with a NULL state or attributes are skipped. Destroyed objects keep their pinned payload, so only their attributes change. API output is unchanged; unparsable rows are skipped with a warning

## Build

- Bump the workspace version to 5.30.0. The k8s proto crate pins and the `cosmian_kms_server_database` version now come from the root workspace, so `release.sh` only seds the root `Cargo.toml` and the docs
