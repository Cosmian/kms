## Bug Fixes

### Database
- Add a 6.0.0 startup migration step (`StoredStateSync`) on SQLite, PostgreSQL, MySQL/MariaDB and Redis with Findex that writes the state clients already see (the lifecycle column; a `PreActive` column defers to the attributes) into the stored attributes and key-block attributes, which lagged the column after `Deactivate`, `Destroy` and `Revoke`. Destroyed objects keep their pinned payload, so only their attributes change. API output is unchanged; unparsable rows are skipped with a warning

## Build

- Bump the workspace version to 6.0.0 and add `crate/clients/k8s/plugin/Cargo.toml` to `release.sh`, which missed its `cosmian_kms_k8s_plugin_proto` version pin
