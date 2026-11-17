---
name: 'Database Version Compatibility'
description: 'Upgrade, downgrade (N-1), round-trip and mixed-version rules for SQL and Redis-with-Findex storage changes'
applyTo: 'crate/server_database/**, crate/kmip/src/kmip_0/kmip_types.rs, crate/kmip/src/kmip_2_1/kmip_attributes.rs, crate/kmip/src/kmip_2_1/kmip_objects.rs, crate/kmip/src/kmip_2_1/kmip_types.rs'
---

# Database version compatibility

Scope: any change to what is stored, or how it is stored, in SQL (`*.sql`, store `.rs` files), in Redis-with-Findex, or in the serde form of persisted KMIP types (`Object`, `Attributes` and the enums they contain). For the KMIP files the rules apply only when the edited type is reachable from `Object`/`Attributes`.

## Policy

N-1: the previous release must start and serve on a database written by this version. An unavoidable gap must be documented, with a manual recovery. A change that breaks N-1 needs explicit user approval before it is implemented.

Verdicts:

- `SAFE`: N-1 starts and serves with no loss.
- `DEGRADED`: works with a documented gap and a manual recovery.
- `BREAKING`: N-1 cannot start, or cannot read existing data. Needs explicit user approval before implementation, plus an expand/contract split across two releases.

## How versions are handled today

- **SQL has no version check.** `instantiate` in `crate/server_database/src/stores/sql/{sqlite,pgsql,mysql}.rs` writes `db_version`/`db_state` only inside `if clear_database { … }`. It never compares versions, so an older binary starts on a newer database. Tables use `CREATE TABLE IF NOT EXISTS`, and idempotent migrations run on every start. One-time backfills are gated by `parameters` markers (`WRAPPING_KEY_BACKFILL_PARAM`, `CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM` in `stores/migrate.rs`); a marker stays set after a downgrade.
- **Redis checks markers, not version values.** `RedisWithFindex::instantiate` (`stores/redis/redis_with_findex.rs`) refuses a non-empty database that lacks `db_version` or has `db_state != ready`, but never compares the version value. Older code only reads key prefixes it knows (`do::*` SCANs in `stores/redis/objects_db.rs`). `clear_database` does `FLUSHDB`.
- **Objects are stored as JSON.** SQL stores `serde_json` of `Object` and `Attributes` in the `objects.object` / `objects.attributes` columns. Redis stores AES-256-GCM-encrypted `serde_json` of `RedisDbObject`. `crate/kmip/src` has no `deny_unknown_fields`, and `Attributes` fields are `Option` with `skip_serializing_if = "Option::is_none"`.

## Change classification

| # | Change | Upgrade requirement | N-1 / round-trip effect | Verdict and required action |
|---|---|---|---|---|
| 1 | **New table.** | `CREATE TABLE IF NOT EXISTS` in every backend file, executed at startup. | N-1 ignores the table. | SAFE. If the rows are keyed by `objects.id`, row 7 also applies. |
| 2 | **New column.** | Nullable or `DEFAULT`, added idempotently (`ADD COLUMN IF NOT EXISTS`; on SQLite/MySQL check `PRAGMA table_info` / `SHOW COLUMNS` first). | N-1 inserts with explicit column lists, so rows it writes get NULL/DEFAULT. | SAFE only if new code accepts NULL/DEFAULT on such rows. `NOT NULL` without `DEFAULT` is BREAKING. |
| 3 | **New index.** | `CREATE INDEX IF NOT EXISTS`. | Harmless for N-1. | SAFE. Document the first-start cost in `tables.md`. |
| 4 | **Drop or rename a table or column; change a type, constraint or primary key.** | n/a | N-1 queries fail. | BREAKING. Expand/contract: release N adds the new form and keeps writing the old one; release N+1 removes the old one. |
| 5 | **New persisted enum variant or `Object` variant; `#[serde(rename)]`; changed representation of an existing value.** | n/a | N-1 fails to deserialize every row that holds the new value, so those objects become unreadable on N-1. | A new variant is DEGRADED: the CHANGELOG must name the affected objects. Changing the representation of an existing value is BREAKING. |
| 6 | **New `Option` field in `Attributes` or another persisted struct.** | Must carry `skip_serializing_if = "Option::is_none"`. | N-1 ignores the field when reading, then drops it when it rewrites the row (any update). | DEGRADED. Document which attribute is lost when N-1 updates the object. |
| 7 | **New derived or side data keyed by object UID** (counter tables/keys such as `gcm_invocations`, index columns such as `wrapping_key_id`, Findex keywords, system tags). | Reconcile idempotently on every startup, as `purge-orphan-gcm-invocations` and `purge_orphan_gcm_invocations` do. | N-1 neither maintains nor deletes this data. After re-upgrade there are orphans (deleted objects, including after N-1 `clear_database`), stale values, or missing values (objects N-1 created). | Never rely on a one-time `parameters` marker alone: it stays set after a downgrade. If the data cannot be reconciled (for example, operations N-1 performed without counting), the verdict is DEGRADED and must be documented. |
| 8 | **New `parameters` row or one-time marker.** | n/a | Harmless for N-1. | SAFE. For round-trip effects, see row 7. |
| 9 | **New Redis key prefix.** | n/a | N-1 never scans it, and `FLUSHDB` clears it. | SAFE. If the data is UID-keyed, row 7 applies. |
| 10 | **Changed Redis encryption, KDF, key name format, Findex keyword encoding, or `RedisDbObject` serde names.** | n/a | N-1 cannot read the data. | BREAKING. |
| 11 | **New `clean-table-*` entry or other clear-path change.** | n/a | N-1's `clear_database` does not clear the new table. | Row 7 reconciliation covers it. |

## Mixed versions (HA rolling restart)

N-1 and N run at the same time on one database, so every N-1 effect above also happens concurrently. A startup reconcile only runs at the next restart of an N instance. In a multi-instance Redis setup, reconciliation must not delete data for a UID whose `do::` key exists.

## Required in the same change

- (a) Add a `**Downgrade.**` paragraph to the affected `` ## `table` `` section of `documentation/docs/configuration/database/tables.md`, modeled on § `gcm_invocations`. For Redis layout changes, update `documentation/docs/configuration/database/redis.md` § Migration. List every DEGRADED/BREAKING item in the branch CHANGELOG.
- (b) For row 7, add a test that writes the derived data, re-instantiates the store with `clear_database=false`, and asserts the reconciled state. Model it on `gcm_invocations_orphan_purge_test` in `crate/server_database/src/tests/database_tests.rs`, and call it from `test_db_sqlite`, `test_db_postgresql`, `test_db_mysql` and `test_db_redis_with_findex` in `crate/server_database/src/tests/mod.rs`.
- (c) Run `/kms-db-compat` and paste its table into the PR description.

Workflow and commands: `/kms-db-compat`. Schema docs: `database-tables.instructions.md`.
