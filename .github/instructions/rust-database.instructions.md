---
name: 'Rust Database Backends'
description: 'Database backend implementation rules (SQLite, PostgreSQL, Redis-findex)'
applyTo: 'crate/server_database/**/*.rs'
---

# Database backend rules

## Architecture

- All backends implement traits defined in `cosmian_kms_interfaces` (`crate/interfaces/`).
- Supported backends: SQLite (default), PostgreSQL, MySQL/MariaDB/Percona, Redis-findex.
- Redis-findex is gated with `#[cfg(feature = "non-fips")]` — it is not available in FIPS mode.

## Object storage contract

- Objects are stored as TTLV-serialized bytes with associated metadata (state, owner, permissions).
- Object UIDs are server-generated UUIDs unless the client provides one.
- Permissions are stored separately from objects.

## Transaction safety

- Use database transactions for multi-step operations (create + set permissions).
- SQLite: use WAL mode for concurrent read access.
- PostgreSQL: use `SERIALIZABLE` isolation for key state transitions.

## Testing

Requires running database backends:

```bash
docker compose up -d           # starts postgres, redis, etc.
cargo test -p cosmian_kms_server_database
cargo test -p cosmian_kms_server_database --features non-fips  # includes Redis-findex
```

Environment variables for test backends:

| Variable | Value |
|----------|-------|
| `KMS_POSTGRES_URL` | `postgresql://kms:kms@127.0.0.1:5432/kms` |
| `KMS_MYSQL_URL` | `mysql://kms:kms@localhost:3306/kms` |
| `KMS_SQLITE_PATH` | `data/shared` |
