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

## Versioned migrations

- Data transformations between KMS versions **MUST** be registered as a `MigrationStep` in `crate/server_database/src/stores/migrate.rs`, never as another inline startup backfill.
- Additive, idempotent DDL belongs in `ensure_schema`. DDL that converts existing data is a data transformation and must be versioned.
- The runner owns completion-marker reads and writes, version checkpoints and migration state. Backend `apply_step` implementations perform only the idempotent data transformation.
- Startup must acquire the backend lock and perform the read-only newer-version check before any application-schema DDL. Backend lock-infrastructure initialization may precede the check when required to acquire the lock. Hold the lock through the final `ready` stamp and use a drop guard to release it on both success and errors. Never delete SQLite's sidecar lock file.

When adding a migration step:

1. Add its `MigrationStep` variant, `version()` and `marker()`, then append it to `MIGRATION_STEPS` in strictly ascending version order. The running package version must include the last registered step.
2. Implement the new match arm in every backend's `apply_step`: SQLite, PostgreSQL, MySQL and Redis. All four backends are wired into the migration runner; backend-specific steps keep a no-op arm on the other backends.
3. Extend the migration scenarios and released fixtures. Verify both step-by-step and direct upgrades, data preservation, marker skips, interrupted runs and concurrent startup.

## Documentation

Keep the database documentation under `documentation/docs/configuration/` in sync whenever the
schema or backend behaviour changes:

- `documentation/docs/configuration/database/configuration.md` — the Databases overview (selection, configuration, TLS, migration).
- `documentation/docs/configuration/database/tables.md` — the tables and the links between them (update when adding/altering/removing a table, column, or index).
- `documentation/docs/configuration/database/redis.md` — the Redis-with-Findex backend (update when changing the encryption model, key derivation, or data layout).

When adding or removing a page, also update the navigation in `documentation/docs/SUMMARY.md` and
`documentation/nav.yml`.

> Run `/threat-model` when database changes alter trust boundaries, authorization, or security-relevant data flows; skip only for a confirmed incremental change outside those areas.

## SQL statements live in SQL files

- Every SQL statement (queries, DDL, migrations, `PRAGMA`/`SET SESSION`, health checks) MUST be a named entry in the backend's `.sql` file, never a string literal in a `.rs` file:
    - `query.sql` — PostgreSQL, and the shared base that SQLite inherits;
    - `query_sqlite.sql` — SQLite overrides (loaded after `query.sql`; same name wins);
    - `query_mysql.sql` — MySQL/MariaDB (standalone, no fallback to `query.sql`).
    - `stores/audit/audit.sql` — the audit store (PostgreSQL).
- Fetch them by name with `get_pgsql_query!`, `get_sqlite_query!`, `get_mysql_query!` or `SqlDatabase::get_query`. Resolve the name before entering a `call(|c| …)` closure and move the `&'static str` in.
- Adding a schema change means adding the statement to every backend file that needs it, plus the idempotent migration step that runs it at startup (`ADD COLUMN IF NOT EXISTS`; on SQLite/MySQL check `PRAGMA table_info` / `SHOW COLUMNS` first).
- The `rawsql` loader has parsing pitfalls (a query ends at the first line ending in `;`, so multi-statement entries go on one line; no `name` in comments) — see `database-tables.instructions.md` § `rawsql` loader gotcha.
- Exceptions: (1) SQL assembled at runtime from user-supplied filters (`locate_query.rs`, `format!` with bind placeholders); (2) `#[cfg(test)]` code and test fixtures (tamper/trigger tests, legacy-schema fixtures in `tests/`). Any other inline SQL in non-test code is a review finding.
