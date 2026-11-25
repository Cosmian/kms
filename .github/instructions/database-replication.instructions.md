---
name: 'Database Cluster and Multi-Region Impact'
description: 'Cluster (several KMS instances on one database) and multi-region (PostgreSQL Spock, MySQL Galera) decisions to take whenever a database change adds, alters or relies on stored data'
applyTo: 'crate/server_database/**, crate/interfaces/src/stores/**, **/*.sql'
---

# Database change: cluster and multi-region impact

Scope: any change to what the server stores, or to the SQL, Redis or trait code that stores it (new table, column, index, key prefix, trigger, `parameters` row, lock, counter, `PermissionsStore` / `ObjectsStore` method), **and** any new in-process state (`Mutex<HashMap>`, `OnceLock`, static cache, `Arc<Mutex<..>>` in `crate/server`) that another KMS instance or region would also need to see.

A change here is not finished until the cluster and multi-region questions below are answered in the PR. Compatibility with the previous release is a separate gate: `database-compatibility.instructions.md`.

## Deployment modes

| Mode | Topology | What it means for stored data |
|---|---|---|
| Single node | One KMS, one database | Nothing to coordinate. |
| Cluster (HA) | Several KMS instances on **one** shared database (PostgreSQL, MySQL/MariaDB, Redis-with-Findex), behind a load balancer | The database is shared, so a row is visible to every instance at once. **Process memory is not shared**: any state that must be seen by every instance (revocations, locks, counters, election) lives in the database, not in a `static` or a struct field. Background jobs must not run twice (`kms_cron_locks`, leader election). |
| Multi-region, PostgreSQL | One PostgreSQL per region, joined by Spock logical multi-master replication (`documentation/docs/configuration/database/multi_region.md`, ADR `2026-09-19-multi-region-active-active-postgresql`) | Replication is asynchronous and active-active: two regions can write the same row. The KMS does not call Spock: the operator wires the replication set. |
| Multi-region, MySQL | Galera cluster (synchronous certification-based replication) | Every InnoDB table with a `PRIMARY KEY` replicates; no table can be excluded. |

## Mandatory decisions, one per new table, column or stored value

Put the answers in the `##`table`` section of `documentation/docs/configuration/database/tables.md` (a **Replication.** paragraph next to **Downgrade.**) and in the PR description.

1. **Cluster.** Is the data read by an instance other than the one that wrote it? If yes it MUST be in the database (SQL and Redis-with-Findex), with the same idempotent startup creation as every other table. A per-process copy is only a cache with a stated maximum staleness. Fail closed when a security decision depends on a read that fails.
2. **Multi-region PostgreSQL: replicated or node-local?** The default is replicated: `spock.repset_add_all_tables('default', ARRAY['public'])` adds every `public` table. A node-local table (like `cluster_nodes`) needs an explicit `spock.repset_remove_table` and is guarded by `mr_guard_cluster_tables`.
3. **Replication prerequisites.** Every replicated table has a real `PRIMARY KEY` (REPLICA IDENTITY DEFAULT); no table relies on a nullable unique index. Add the new primary key to `mr_guard_primary_keys` in `.mise/lib/multi_region_guards.sh` (PostgreSQL) and keep the table InnoDB (`mr_guard_mysql_primary_keys`).
4. **Conflict class.** State which one applies and design the write for it:
   - *insert-only* or *idempotent* rows keyed by a random id (an `INSERT ... ON CONFLICT DO NOTHING` is enough);
   - *last-update-wins* (accepted only when losing one side is harmless; say so);
   - *counter* (read-modify-write): needs Spock delta-apply (`log_old_value = true, delta_apply_function = spock.delta_apply`), as `gcm_invocations.count`;
   - *single-writer* (only the leader region writes): gate the writer on `require_leader_region` and let followers only read.
   A read-modify-write on a replicated row with no delta-apply is a bug.
5. **Existing deployments.** `repset_add_all_tables` ran at setup, so a new table does not replicate on an upgraded multi-region deployment until the operator runs `SELECT spock.repset_add_table('default', '<table>');` on every node. Document it in `multi_region.md` and as a **Setup action** in the branch CHANGELOG.
6. **Triggers and advisory locks.** PostgreSQL advisory locks and `UNLOGGED` tables are local to one database. A trigger that must fire on replicated rows is `ENABLE ALWAYS` (see `mr_guard_state_event_triggers`).
7. **Lag window.** State the staleness a region can observe (asynchronous replication), and whether a security decision (logout, revoke, destroy) can be replayed in that window. Record it in the docs; do not claim cross-region immediacy.

## Required in the same change

- (a) `tables.md`: a **Replication.** paragraph (mode by mode: cluster, Spock, Galera, Redis) for each new table.
- (b) `multi_region.md` and ADR consequences: the operator step for existing deployments, the conflict class, the lag window. Update the replication-set commands if the table is node-local.
- (c) `.mise/lib/multi_region_guards.sh`: extend the guard that matches the decision (primary key list, node-local tables, delta-apply).
- (d) A behavioural scenario in the live two-node tests: `test_db_pgedge_active_active` (numbered `S<n>`, uses `set_replication` to partition) and `test_db_galera_active_active` (`G<n>`), in `crate/server_database/src/tests/mod.rs`. Cover the write on one node read on the other, and the concurrent write of the same key while partitioned. Run them with `mise run test:db:pgedge` and `mise run test:db:galera`, and require `1 passed`; an `ignored` result is not a proof.
- (e) If a cluster-mode decision moved state from process memory to the database, a unit test with two instances sharing one store (see `a_logout_on_one_instance_revokes_the_session_on_every_instance` in `crate/server/src/middlewares/ui_session.rs`).
- (f) Run `/kms-db-compat`: its table now carries a **Cluster / multi-region** verdict per change.

## Quick detection (agents)

Run these on the diff before answering the decisions above; any hit means this file applies:

```bash
BASE="${1:-origin/develop}"; git rev-parse -q --verify "$BASE" >/dev/null || BASE=HEAD~1
git diff "$(git merge-base "$BASE" HEAD)" -- crate/server_database crate/interfaces/src/stores '*.sql' | grep -nE '^\+.*(CREATE TABLE|ALTER TABLE|CREATE INDEX|CREATE TRIGGER|-- name:|PermissionsStore|ObjectsStore|ui_session|cron_lock|advisory)'
git diff "$(git merge-base "$BASE" HEAD)" -- crate/server/src | grep -nE '^\+.*(Mutex<(Hash|BTree)|OnceLock|LazyLock|static [A-Z_]+:|moka|Cache)'
```

A `+` line from the second command is process-local state: apply decision 1.
