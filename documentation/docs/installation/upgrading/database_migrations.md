# Database Migrations

When you start a newer KMS binary against an existing database, the server checks the stored database version and applies any required schema or data updates automatically before opening its HTTP and KMIP ports. Once the update completes, the server records the new version and begins serving requests. Subsequent restarts at the same version start immediately without re-running completed steps.

For KMIP protocol and client behavior changes when upgrading to 6.0, see [Upgrading from 5.x to 6.0](./upgrade_5_to_6.md).

## Supported source versions

You can upgrade directly to the current release without installing intermediate versions in between, subject to the version boundaries below:

| Backend | `5.20.0` or later | Older `5.x` releases | Earlier versions |
| --- | --- | --- | --- |
| **SQLite**, **PostgreSQL**, **MySQL**, **MariaDB**, **Percona XtraDB Cluster** | Automatic in-place upgrade at startup. | `5.0.0`–`5.19.x`: logs a warning at startup and applies all pending updates. | `< 5.0.0`: export all objects from the old KMS, initialize an empty database on the new KMS, and import them. |
| **Redis with Findex** *(non-FIPS only)* | Automatic in-place upgrade at startup. | `5.12.0`–`5.19.x`: logs a warning at startup and applies all pending updates. | `< 5.12.0`: startup is refused. Export all objects from the old KMS, initialize an empty Redis database on the new KMS, and import them. |

On large databases, the first startup after an upgrade takes longer than a normal boot while new indexes or data backfills run.

## Before you upgrade

1. **Stop running instances of the previous version.** Starting a new KMS binary does not stop older KMS nodes that are already connected to the database. Shut down the older instances before starting the new release so they do not write stale records during the upgrade.
2. **Back up the database while the KMS is stopped.** For SQLite, copy the entire `sqlite_path` directory (`cp -a`). For PostgreSQL, MySQL, MariaDB, Percona XtraDB Cluster, and Redis, take a cold dump or snapshot with your database's backup tool.

## Multiple instances and high availability

If several KMS instances of the new version start concurrently against the same database, one instance runs the migration while the others wait before opening their HTTP and KMIP listeners (retrying for up to 31 minutes). As soon as the first instance finishes, the waiting instances observe the updated database version and start serving traffic.

!!! warning "Deployment requirements during upgrades"
    - **PostgreSQL behind PgBouncer**: connect to PostgreSQL directly or use `session` pool mode. `transaction` pool mode cannot hold the startup coordination lock across statements.
    - **MySQL Galera and Percona XtraDB Cluster**: point all starting KMS instances at the same database node during the upgrade. Startup coordination on MySQL-family clusters is local to a single node.
    - **SQLite**: leave `<sqlite_path>/kms.db.migration.lock` in place on disk. Sharing a SQLite database across processes requires a filesystem that supports OS file locks.
    - **Redis with Findex** *(non-FIPS only)*: if a migrating KMS process is terminated with `SIGKILL` mid-upgrade, newly started instances wait up to 30 minutes for the previous startup lease to expire unless `kms_db_migration_lock` is deleted after confirming no other KMS instance is running.

## Interrupted upgrades

Every migration step is safe to resume. If the KMS process or database stops before an upgrade finishes, start the new KMS binary again; it detects the unfinished run, skips steps that already completed, and finishes the remaining work.

## Downgrades and recovery

Starting an older KMS binary against a database that has already been opened by a newer version is refused before any schema or data changes run:

```text
Database version X is newer than this KMS server version Y: refusing to start. Upgrade the KMS server to X or later.
```

To revert to a previous KMS release without losing data, stop the new KMS instances, restore your pre-upgrade database backup, and start the previous KMS binary.

!!! note "Resetting a test database"
    Starting the server with `--clear-database` (or `clear_database = true` under `[db]` in `kms.toml`) deletes all stored objects and resets the recorded database version to the running binary. Never use `--clear-database` on production data you intend to keep.

## Clustered MySQL databases created before 5.14.0

Databases created on MySQL before KMS `5.14.0` declared `UNIQUE` indexes rather than `PRIMARY KEY` constraints on `tags` and `read_access`. New installations on `5.14.0` or later already have primary keys. If you are upgrading a pre-`5.14.0` database onto a cluster that enforces primary keys (such as Percona XtraDB Cluster with `pxc_strict_mode=ENFORCING` or MariaDB Galera), run the following statements as a privileged MySQL user while KMS traffic is stopped before starting the new server:

```sql
ALTER TABLE tags
    DROP INDEX id,
    MODIFY id VARCHAR(128) NOT NULL,
    MODIFY tag VARCHAR(255) NOT NULL,
    ADD PRIMARY KEY (id, tag);

ALTER TABLE read_access
    DROP INDEX id,
    MODIFY id VARCHAR(128) NOT NULL,
    MODIFY userid VARCHAR(255) NOT NULL,
    ADD PRIMARY KEY (id, userid);
```
