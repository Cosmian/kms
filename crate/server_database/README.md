# Cosmian KMS Server Database

This crate implements the database layer that handles persistent storage of cryptographic objects, metadata, access control information, and logs. It supports multiple database backends and provides a unified interface for all storage operations.

## Supported Database Backends

- **SQLite**: Development and single-node deployments (`--database-type sqlite`)
- **PostgreSQL**: Production deployments with replication (`--database-type postgresql`)
- **MySQL/MariaDB**: Production deployments (`--database-type mysql`)
- **Redis (with Findex)**: Encrypted searchable storage (`--database-type redis-findex`, **not available in FIPS mode**)

## Database Schema

### SQL Databases (SQLite, PostgreSQL, MySQL)

```mermaid
erDiagram
    parameters {
        varchar name PK "VARCHAR(128)"
        varchar value "VARCHAR(256)"
    }
    objects {
        varchar id PK "VARCHAR(128) — Object UID"
        varchar object "VARCHAR/LONGTEXT — Serialized KMIP object"
        json attributes "KMIP attributes"
        varchar state "VARCHAR(32) — Object state"
        varchar owner "VARCHAR(255) — Owner user ID"
    }
    read_access {
        varchar id FK "VARCHAR(128) — Object UID"
        varchar userid "VARCHAR(255) — User ID"
        json permissions "Array of operations"
    }
    tags {
        varchar id FK "VARCHAR(128) — Object UID"
        varchar tag "VARCHAR(255) — Tag value"
    }
    objects ||--o{ read_access : "has permissions"
    objects ||--o{ tags : "has tags"
```

### Redis with Findex

The schema below use the following legend :

- ENC_KMS(...) = Data encrypted with KMS
- ENC_Findex(...) = Data encrypted with Findex
- permission_triplet = Tuple(user_id, obj_uid, permission)
- metadata = Object owner, tags, and other attributes

| Key | Value |
|-----|-------|
| `db_version` | Last KMS version migrated to (`>= 5.12.0`; updated after each migration step and on completion) |
| `db_state` | `"ready"` \| `"upgrading"` |
| `wrapping_key_id_backfilled` | `"true"` once the `5.25.0` `wrapped_by::<uid>` Findex backfill has completed |
| `certificate_serial_tag_backfilled` | `"true"` once the `5.29.0` `_serial=<HEX>` certificate tag backfill has completed |
| `kms_db_migration_lock` | Ephemeral UUID v4 lease token (`SET ... NX PX 1800000`, released via Lua compare-and-delete) serializing startup migrations |
| `do::<object_uid>` | `ENC_KMS(object data)` |
| `ENC_Findex v8(o:obj_uid)` | `ENC_Findex v8(permission_triplet)` |
| `ENC_Findex v8(u:userid)` | `ENC_Findex v8(permission_triplet)` |
| `ENC_Findex v8(object_uid)` | `ENC_Findex v8(metadata)` |

A more colorful and clear description of how the Redis backend operates with Findex can be red on the its original PR description : [github.com/Cosmian/kms/pull/542](https://github.com/Cosmian/kms/pull/542).

### Environment Variables

- `KMS_POSTGRES_URL`: PostgreSQL connection string
- `KMS_MYSQL_URL`: MySQL/MariaDB connection string
- `KMS_SQLITE_PATH`: SQLite database file path
- `KMS_REDIS_URL`: Redis connection string for Findex

### Connection Examples

```bash
# PostgreSQL
KMS_POSTGRES_URL=postgresql://user:password@host:5432/database

# MySQL
KMS_MYSQL_URL=mysql://user:password@host:3306/database

# SQLite
KMS_SQLITE_PATH=/path/to/database.db

# Redis (for Findex)
KMS_REDIS_URL=redis://host:6379
```

## Schema Changes and Migrations

Startup migrations are driven by `Migrate::bootstrap` in [`src/stores/migrate.rs`][migrate-rs].

### Adding a SQL Table, Nullable Column, or Index

Additive schema DDL with no existing-row conversion belongs in `Migrate::ensure_schema`, not in `Migrate::apply_step`:

1. Add named `CREATE TABLE IF NOT EXISTS` and `clean-table-*` queries in [`query.sql`][query-sql] and [`query_mysql.sql`][query-mysql] (plus [`query_sqlite.sql`][query-sqlite] if SQLite syntax differs).
2. Run the DDL in `Migrate::ensure_schema` across [`sqlite.rs`][sqlite-rs], [`pgsql.rs`][pgsql-rs], and [`mysql.rs`][mysql-rs], and include `clean-table-*` in the `clear_database` path.
3. If rows reference `objects.id`, reconcile orphans idempotently on every boot in `ensure_schema` rather than behind a one-time marker, because an N-1 downgrade leaves markers set.
4. Document the table in [`tables.md`][tables-md] (table count, overview row, columns, ER diagram, and `**Downgrade.**` note).

### Adding a Versioned Data Migration (`apply_step`)

One-time backfills or format conversions across releases are registered in [`src/stores/migrate.rs`][migrate-rs]:

1. Add a `MigrationStep` variant with its target `version()` and completion `marker()`, then append it to `MIGRATION_STEPS` in strictly ascending version order.
2. Implement the match arm in `Migrate::apply_step` in all four backends ([`sqlite.rs`][sqlite-rs], [`pgsql.rs`][pgsql-rs], [`mysql.rs`][mysql-rs], [`redis/migrations/mod.rs`][redis-mig]), returning `Ok(())` where inapplicable.
3. Keep `apply_step` idempotent and limited to the data change: the runner owns startup locks, `db_state`, completion markers, and `db_version` checkpoints.
4. Extend the migration scenario tests under `src/tests/` and the released fixtures documented in [`test_data/db_migration/README.md`][fixtures-readme].

[migrate-rs]: ./src/stores/migrate.rs
[query-sql]: ./src/stores/sql/query.sql
[query-mysql]: ./src/stores/sql/query_mysql.sql
[query-sqlite]: ./src/stores/sql/query_sqlite.sql
[sqlite-rs]: ./src/stores/sql/sqlite.rs
[pgsql-rs]: ./src/stores/sql/pgsql.rs
[mysql-rs]: ./src/stores/sql/mysql.rs
[redis-mig]: ./src/stores/redis/migrations/mod.rs
[tables-md]: ../../documentation/docs/configuration/database/tables.md
[fixtures-readme]: ../../test_data/db_migration/README.md

## Security

- **Encryption**: All sensitive data is encrypted before storage
- **Access Control**: Database-level and application-level security
- **Logging**: Complete audit trail of all operations

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
