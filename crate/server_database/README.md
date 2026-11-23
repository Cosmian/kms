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

## Object Lifecycle State

The KMIP lifecycle state of an object (`PreActive`, `Active`, `Deactivated`, `Compromised`, `Destroyed`,
`Destroyed_Compromised`) is stored in `objects.state`. The two multi-region backends, PostgreSQL and MySQL, apply
the same merge rule when two writers change the state of one object at the same time, but they reach it differently,
because their replication differs: PostgreSQL with Spock replicates committed rows and merges them afterwards, while
MySQL Galera serializes concurrent writers and retries the loser. SQLite and Redis-with-Findex have a single writer,
are not multi-region targets, and write the new state as is, without a join.

### The merge rule

The states are joined, not overwritten: the later phase wins and a compromise is never forgotten. The join is
commutative, associative and idempotent, so every node reaches the same state whatever order the changes arrive in.
It is implemented twice with the same order: `kms_state_join` in
[`pgsql_object_state_events.sql`][pgsql-events-sql] and `join_state` in [`mysql.rs`][mysql-rs].

```mermaid
flowchart LR
    classDef phase fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#000
    classDef final fill:#f8cecc,stroke:#b85450,stroke-width:2px,color:#000

    pre["PreActive<br/>phase 1"]:::phase --> act["Active<br/>phase 2"]:::phase
    act --> deact["Deactivated<br/>phase 3"]:::phase
    act --> comp["Compromised<br/>phase 3"]:::phase
    deact --> dest["Destroyed<br/>phase 4"]:::final
    comp --> destcomp["Destroyed_Compromised<br/>phase 4"]:::final
    comp -.->|"join with Destroyed"| destcomp
```

- The result has the highest phase of the two states.
- If either state is `Compromised` or `Destroyed_Compromised`, the result is the compromised variant of that phase.
- Example: joining `Destroyed` and `Deactivated` gives `Destroyed`; joining `Destroyed` and `Compromised` gives
  `Destroyed_Compromised`.
- Batch UNDO is the only way back: `update_state_allow_downgrade` replaces the observed state.

### PostgreSQL: an insert-only event log

Spock resolves a conflict on one row by last-update-wins, so two regions writing `objects.state` would lose one of
the changes. PostgreSQL therefore never writes `objects.state` for a transition. It inserts an event, and a trigger
derives the state from the events. Events are insert-only rows with random UUIDs, so they never conflict and both
regions end with the same set of events.

```mermaid
flowchart TB
    classDef table fill:#ffe6cc,stroke:#d79b00,stroke-width:2px,color:#000
    classDef trigger fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#000
    classDef code fill:#e1d5e7,stroke:#9673a6,stroke-width:2px,color:#000

    api["update_state<br/>update_state_allow_downgrade<br/>create, Upsert, delete"]:::code
    events[("object_state_events<br/>event_id, object_id, state,<br/>object, wrapping_key_id")]:::table
    tombs[("object_state_event_tombstones<br/>event_id")]:::table
    apply["AFTER INSERT triggers<br/>touch the objects row,<br/>version + 1"]:::trigger
    derive["BEFORE INSERT OR UPDATE trigger<br/>objects_state_derive"]:::trigger
    eff["kms_effective_state<br/>joins the events<br/>that have no tombstone"]:::trigger
    objects[("objects<br/>state, object,<br/>wrapping_key_id, version")]:::table

    api -->|"insert an event"| events
    api -->|"insert a tombstone<br/>(UNDO, reused uid)"| tombs
    events --> apply
    tombs --> apply
    apply --> objects
    objects --> derive
    derive --> eff
    eff --> events
    derive -->|"overwrites state, and the<br/>zeroized payload when destroyed"| objects
```

| Code path in [`pgsql.rs`][pgsql-rs] | What it writes |
| ----------------------------------- | -------------- |
| `create`, `Upsert` | Tombstones the leftover events of a reused UID, inserts the `objects` row, then one event with the initial state, in one transaction |
| `update_state`, `AtomicOperation::UpdateState` | One event with the new state; never an `UPDATE` of `objects.state` |
| `update_state_allow_downgrade`, `AtomicOperation::ResetState` | Tombstones the events this node has observed, then one event with the replacement state |
| `delete` | Deletes the tombstones and events of the object in the same transaction as the object |
| `ensure_schema` (every startup) | Purges events of objects that no longer exist, gives every event-less object a baseline event |

- **Destroyed events carry the payload.** For `Destroyed` and `Destroyed_Compromised`, the event stores a copy of the
  zeroized `object` and `wrapping_key_id`, and the derive trigger restores them on the row. A replicated older
  payload therefore cannot bring key material back.
- **Tombstones are observed-remove.** A tombstone names events, so UNDO removes only the events this node has seen;
  an event created concurrently in another region and not yet received still counts.
- **Versions advance.** The apply triggers bump `objects.version`, so a conditional write planned on a snapshot taken
  before a transition fails instead of overwriting it.
- **All the triggers are `ENABLE ALWAYS`**, so they also fire on rows applied by replication.

Concurrent changes in two regions:

```mermaid
sequenceDiagram
    participant EU as KMS EU
    participant DB_EU as PostgreSQL EU
    participant DB_US as PostgreSQL US
    participant US as KMS US

    EU->>DB_EU: Destroy key K
    DB_EU->>DB_EU: insert event Destroyed (with zeroized payload)
    US->>DB_US: Deactivate key K
    DB_US->>DB_US: insert event Deactivated
    Note over DB_EU,DB_US: Spock replicates the events in both directions
    DB_EU->>DB_US: event Destroyed
    DB_US->>DB_EU: event Deactivated
    DB_EU->>DB_EU: derive trigger joins both events, state is Destroyed
    DB_US->>DB_US: derive trigger joins both events, state is Destroyed
```

### MySQL (Galera): a row lock and a retry

Galera certifies each transaction at commit: a transaction that changes a row another node changed concurrently fails
certification (error 1213) and the KMS retries it. No conflicting rows ever have to be merged, so MySQL has no event
log. `update_state_` in [`mysql.rs`][mysql-rs] reads the stored state with `SELECT … FOR UPDATE`, joins it with the
new state using `join_state`, and writes the result with `version + 1`. The retry then runs on the fresh row and
joins again.

```mermaid
sequenceDiagram
    participant KMS_A as KMS on node A
    participant Galera_A as Galera node A
    participant Galera_B as Galera node B
    participant KMS_B as KMS on node B

    KMS_A->>Galera_A: SELECT state FOR UPDATE
    KMS_B->>Galera_B: SELECT state FOR UPDATE
    KMS_A->>Galera_A: write join(stored, Destroyed), version + 1
    KMS_B->>Galera_B: write join(stored, Deactivated), version + 1
    Galera_A->>Galera_B: commit certification
    Galera_B-->>KMS_B: error 1213, transaction aborted
    KMS_B->>Galera_B: retry: SELECT state FOR UPDATE (now Destroyed)
    KMS_B->>Galera_B: write join(Destroyed, Deactivated) = Destroyed
```

`update_state_allow_downgrade` (batch UNDO) is a plain write on MySQL: the row lock already serializes it.

| | PostgreSQL (Spock) | MySQL (Galera) |
| --- | --- | --- |
| Concurrent writers | Both commit; rows merge after replication | One aborts (1213) and retries |
| State written by the code | An event; the trigger derives `objects.state` | `objects.state` directly, joined under a row lock |
| Extra tables | `object_state_events`, `object_state_event_tombstones` | none |
| UNDO | Tombstones plus a replacement event | Plain write |
| Destroyed payload | Stored in the event and restored by the trigger | Kept by the payload update path of `mysql.rs` |

See [Multi-region active-active deployment](../../documentation/docs/configuration/database/multi_region.md) for the
operator view and [`tables.md`][tables-md] for the columns and the downgrade verdicts.

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
[pgsql-events-sql]: ./src/stores/sql/pgsql_object_state_events.sql
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
