# Databases

By default, the server runs using a [SQLite](https://www.sqlite.org/) database, but it can be configured to use a choice
of databases: SQLite encrypted, [PostgreSQL](https://www.postgresql.org/), [MariaDB](https://mariadb.org/),
[MySQL](https://www.mysql.com/), and [Percona XtraDB Cluster](https://www.percona.com/software/mysql-database/percona-xtradb-cluster),
as well as [Redis](https://redis.io/), using the [Redis-with-Findex](#redis-with-findex) configuration.

## Selecting the database

All databases, except SQLite, can be used in a high-availability setup.

The **SQLite** database can serve high loads and millions of objects, and is very suitable
for scenarios that do not demand high availability.

## Connection Workflow

The following sequence diagram illustrates how the Eviden KMS connects to its backing database backend, initializes pools and schema verification, and processes client requests end-to-end:

```mermaid
sequenceDiagram
    autonumber
    actor Client as KMS Client (CLI / REST / KMIP)
    participant KMS as Eviden KMS Server
    participant Pool as Connection Pool (deadpool-postgres / mysql_async / SQLite)
    participant DB as SQL Database (PostgreSQL / MySQL / SQLite)

    Note over KMS,DB: Server Startup & Pool Initialization
    KMS->>Pool: Initialize pool with credentials & TLS options
    Pool->>DB: Open initial connection(s)
    DB-->>Pool: Connection established
    KMS->>DB: Verify schema & migration markers (parameters table)
    DB-->>KMS: Migration state OK (ready)
    Note over KMS: KMS is operational and ready to serve requests

    Note over Client,DB: End-to-End Operation (e.g. Create / Locate / Rekey)
    Client->>KMS: Request operation (e.g., Create AES key via REST/KMIP)
    KMS->>KMS: Authenticate client & authorize operation
    KMS->>Pool: Acquire pooled connection
    Pool->>DB: Execute parameterized SQL query (INSERT/SELECT)
    DB-->>Pool: Query result / rows affected
    Pool-->>KMS: Return result & release connection to pool
    KMS-->>Client: Return KMIP / REST response
```

## Configuring the database

The database parameters may be configured either:

- the [TOML configuration file](../server_configuration_file.md)
- or the [arguments passed to the server](../server_cli.md) on the command line.

### SQLite

This is the default configuration. To use SQLite, no additional configuration is needed.

=== "kms.toml"

    ```toml
    [db]
    database_type = "sqlite"
    sqlite_path = "./sqlite-data"
    ```

=== "Command line arguments"

    ```sh
    --database-type=sqlite \
    --sqlite-path="./sqlite-data"
    ```

### PostgreSQL

=== "kms.toml"

    ```toml
    [db]
    database_type = "postgresql"
    database_url = "postgres://kms_user:kms_password@pgsql-server:5432/kms"
    ```

=== "Command line arguments"

    ```sh
    --database-type=postgresql \
    --database-url=postgres://kms_user:kms_password@pgsql-server:5432/kms
    ```

!!!info "Setting up a PostgreSQL database"
    Before running the server, a dedicated database with a dedicated user should be created on the PostgreSQL instance.
    These sample instructions create a database called `kms` owned by a user `kms_user` with password `kms_password`:

    1. Connect to psql under user `postgres`

        ```sh
        sudo -u postgres psql  # or `psql -U postgres`
        ```

    2. Create user `kms_user` with password `kms_password`

        ```psql
        create user kms_user with encrypted password 'kms_password';
        ```

    3. Create database `kms` under owner `kms_user`

        ```psql
        create database kms owner=kms_user;
        ```

#### PostgreSQL High-Availability (multi-host)

The KMS supports **multi-host PostgreSQL connection strings** for high-availability deployments
(streaming replication, Patroni, pgBouncer clusters, etc.). The `database-url` value is treated
as a raw string so that `host1:port,host2:port` syntax — which the standard URL parser cannot
handle — is passed directly to the PostgreSQL driver.

Use the `target_session_attrs` query parameter to control which node the driver connects to:

| Value        | Behaviour                                                  |
| ------------ | ---------------------------------------------------------- |
| `read-write` | Connect only to the primary (default for HA)               |
| `any`        | Connect to any available node (suitable for read replicas) |
| `read-only`  | Connect only to a standby                                  |

!!! note "Host order"
    The driver tries hosts **left to right** in the URL. With `target_session_attrs=read-write`,
    standbys are automatically skipped (they return `transaction_read_write=off`), so the primary
    is always found regardless of its position. However, **put the expected primary first** to
    avoid an unnecessary round-trip to the standby on every new connection under normal
    conditions.

**Example — two-node HA cluster (primary listed first):**

=== "kms.toml"

    ```toml
    [db]
    database_type = "postgresql"
    database_url  = "postgresql://kms_user:kms_password@primary:5432,standby:5432/kms?target_session_attrs=read-write"
    ```

=== "Command line arguments"

    ```sh
    --database-type=postgresql \
    --database-url="postgresql://kms_user:kms_password@primary:5432,standby:5432/kms?target_session_attrs=read-write"
    ```

The URL must start with `postgresql://` or `postgres://`; any other scheme is rejected at
startup.

#### Replication and standby writability

!!! warning "A standby is read-only"
    In standard PostgreSQL streaming replication, the standby node operates in **hot standby
    mode**: it accepts read queries but **rejects all writes**. The KMS requires a read-write
    connection for every operation, so `target_session_attrs=read-write` will skip a standby
    automatically — but this also means **the KMS cannot use the standby as a fallback by
    itself**. The standby only becomes usable by the KMS after it has been **promoted** to
    primary.

    Replication is entirely managed by the PostgreSQL infrastructure — the KMS does not
    configure, trigger, or monitor it.

##### Recommended setup: use an HA manager

For automatic failover, deploy an HA manager such as [Patroni](https://patroni.readthedocs.io/),
[pg_auto_failover](https://pg-auto-failover.readthedocs.io/), or
[repmgr](https://www.repmgr.org/). These tools:

1. Monitor the primary continuously.
2. **Promote the standby** when the primary is unreachable.
3. **Demote the old primary** back to standby automatically when it recovers (Patroni uses
   `pg_rewind` to resync it with the new primary's WAL timeline).

The KMS URL requires no change: with `target_session_attrs=read-write` the driver
always connects to whichever node is currently the primary.

**What happens when the primary goes down then comes back up?**

| Phase | State | KMS behaviour |
| ----- | ----- | ------------- |
| Primary down, standby still read-only | No writable node exists | KMS retries exhaust (≤ ~3.2 s), requests fail with a database error |
| HA manager promotes the standby | Standby becomes new primary | KMS reconnects on next retry/request, normal operation resumes |
| Old primary recovers | HA manager demotes it to new standby | Transparent; KMS skips it (read-only) and connects to the new primary |
| Old primary recovers **without** an HA manager | Old primary restarts as a standalone node — **data divergence risk** | Manual intervention required before reconnecting the KMS |

!!! tip "Eliminate URL maintenance with a virtual IP or DNS endpoint"
    After a permanent failover without an HA manager, the roles of `primary:5432` and
    `standby:5432` are reversed. The KMS still works (it finds the read-write node), but it
    tries the old-primary address first on every connection, adding latency. To avoid this,
    front the cluster with a **virtual IP** (Keepalived, AWS RDS Multi-AZ endpoint, Azure
    Flexible Server read-write endpoint, GCP Cloud SQL HA endpoint) and use a single-host
    URL — failover then becomes completely transparent to the KMS.

#### PostgreSQL failover retry

When a PostgreSQL primary fails over, the driver may return transient connection errors before
the new primary is ready. The KMS automatically retries failed queries with **exponential
backoff** for the following PostgreSQL SQLSTATE codes:

| SQLSTATE | Meaning                                             |
| -------- | --------------------------------------------------- |
| `08001`  | `sqlclient_unable_to_establish_sqlconnection`       |
| `08004`  | `sqlserver_rejected_establishment_of_sqlconnection` |
| `57P02`  | `crash_shutdown`                                    |
| `57P03`  | `cannot_connect_now`                                |

No additional configuration is required; the retry behaviour is enabled automatically for all
PostgreSQL connections.

### MySQL, MariaDB, or Percona XtraDB Cluster

The KMS supports MySQL-compatible databases including MySQL, MariaDB, and Percona XtraDB Cluster.
All use the same configuration with `database-type=mysql`.

!!! note Clustering Support
    As of version 5.14.0, the KMS schema includes PRIMARY KEY constraints on all tables,
    making it fully compatible with:

    - **Percona XtraDB Cluster** (with `pxc_strict_mode=ENFORCING`)
    - **MariaDB Galera Cluster**
    - Any MySQL clustering solution requiring PRIMARY KEYs for replication

=== "kms.toml"

    ```toml
    [db]
    database_type = "mysql"
    database_url = "mysql://kms_user:kms_password@mysql-server:3306/kms"
    ```

=== "Command line arguments"

    ```sh
    --database-type=mysql \
    --database-url=mysql://kms_user:kms_password@mysql-server:3306/kms
    ```

For certificate authentication, see [MySQL / MariaDB TLS / mTLS](#mysql--mariadb-tls--mtls).

### Redis with Findex

For Redis-with-Findex configuration, see the dedicated [Redis with Findex](./redis.md#configuration) page.

## Securing database connections with TLS / mTLS

The KMS supports TLS-encrypted connections and mutual TLS (mTLS) client-certificate authentication
for PostgreSQL and MySQL-compatible databases. All TLS parameters are configured directly in the
`database-url` as query parameters — no extra CLI flags or TOML keys are needed.

!!! warning "Production certificates must be issued by a trusted Certificate Authority"
    For production deployments, all TLS certificates (CA, server, and client certificates) must be
    issued by a trusted Certificate Authority (CA). Self-signed certificates should only be used
    for testing and development environments.

    Using certificates from an untrusted or self-signed CA may expose your KMS deployment to
    man-in-the-middle (MITM) attacks and should never be done in production.

### PostgreSQL TLS / mTLS

PostgreSQL TLS is configured using the standard `libpq`-style query parameters in the connection URL.

| Parameter     | Description                                                                             |
| ------------- | --------------------------------------------------------------------------------------- |
| `sslmode`     | TLS mode: `disable`, `allow`, `prefer` (default), `require`, `verify-ca`, `verify-full` |
| `sslrootcert` | Path to the CA certificate (PEM) used to verify the server                              |
| `sslcert`     | Path to the client certificate (PEM) for mTLS                                           |
| `sslkey`      | Path to the client private key (PEM) for mTLS                                           |

**Server-authenticated TLS only** (encrypt the connection and verify the server certificate):

=== "kms.toml"

    ```toml
    [db]
    database_type = "postgresql"
    database_url = "postgres://kms:kms@pgsql-server:5432/kms?sslmode=verify-ca&sslrootcert=/path/to/ca.crt"
    ```

=== "Command line arguments"

    ```sh
    --database-type=postgresql \
    --database-url="postgres://kms:kms@pgsql-server:5432/kms?sslmode=verify-ca&sslrootcert=/path/to/ca.crt"
    ```

**Mutual TLS (mTLS)** (encrypt + verify server certificate + present a client certificate):

=== "kms.toml"

    ```toml
    [db]
    database_type = "postgresql"
    database_url = "postgres://kms:kms@pgsql-server:5432/kms?sslmode=verify-full&sslrootcert=/path/to/ca.crt&sslcert=/path/to/client.crt&sslkey=/path/to/client.key"
    ```

=== "Command line arguments"

    ```sh
    --database-type=postgresql \
    --database-url="postgres://kms:kms@pgsql-server:5432/kms?sslmode=verify-full&sslrootcert=/path/to/ca.crt&sslcert=/path/to/client.crt&sslkey=/path/to/client.key"
    ```

!!! note "sslmode behaviour"
    - `disable` – no TLS at all.
    - `allow` / `prefer` (default) – TLS is used if the server offers it, otherwise the connection
      silently falls back to plaintext. The server certificate is **not** verified.
    - `require` – the connection fails if the server does not support TLS. The server certificate
      is **not** verified, unless `sslrootcert` is also set, in which case it is verified against
      that CA (the hostname is still **not** checked).
    - `verify-ca` – the server certificate is verified against the `sslrootcert` CA but the hostname
      is **not** checked. `sslrootcert` is mandatory: as with `libpq`, the KMS refuses to start
      with `verify-ca` and no `sslrootcert`.
    - `verify-full` – the server certificate is verified against the CA **and** the hostname must match.
      This is the recommended mode for production.

    Any other `sslmode` value is rejected at startup. When `sslrootcert` is set, only that CA is
    trusted (the system CA store is not consulted); `verify-full` without `sslrootcert` verifies
    against the system CA store. All certificates must be in **PEM** format.

### MySQL / MariaDB TLS / mTLS

MySQL TLS is configured using query parameters in the connection URL.
Both dash (`ssl-mode`) and underscore (`ssl_mode`) variants are accepted.

| Parameter                      | Description                                                                   |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `ssl-mode`                     | TLS mode: `DISABLED`, `PREFERRED`, `REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY` |
| `ssl-ca`                       | Path to the CA certificate (PEM) for server verification                      |
| `ssl-client-identity`          | Path to the client PKCS#12 (`.p12`) bundle for mTLS                           |
| `ssl-client-identity-password` | Password protecting the PKCS#12 bundle                                        |

**Server-authenticated TLS only** (encrypt the connection and verify the server certificate):

=== "kms.toml"

    ```toml
    [db]
    database_type = "mysql"
    database_url = "mysql://kms:kms@mysql-server:3306/kms?ssl-mode=VERIFY_CA&ssl-ca=/path/to/ca.crt"
    ```

=== "Command line arguments"

    ```sh
    --database-type=mysql \
    --database-url="mysql://kms:kms@mysql-server:3306/kms?ssl-mode=VERIFY_CA&ssl-ca=/path/to/ca.crt"
    ```

**Mutual TLS (mTLS)** (encrypt + verify server certificate + present a client certificate):

=== "kms.toml"

    ```toml
    [db]
    database_type = "mysql"
    database_url = "mysql://kms:kms@mysql-server:3306/kms?ssl-mode=VERIFY_CA&ssl-ca=/path/to/ca.crt&ssl-client-identity=/path/to/client.p12&ssl-client-identity-password=secret"
    ```

=== "Command line arguments"

    ```sh
    --database-type=mysql \
    --database-url="mysql://kms:kms@mysql-server:3306/kms?ssl-mode=VERIFY_CA&ssl-ca=/path/to/ca.crt&ssl-client-identity=/path/to/client.p12&ssl-client-identity-password=secret"
    ```

!!! note "ssl-mode behaviour"
    - `DISABLED` – no TLS at all.
    - `PREFERRED` / `REQUIRED` – TLS is used but the server certificate is **not** verified.
    - `VERIFY_CA` – the server certificate is verified against the CA.
    - `VERIFY_IDENTITY` – the server certificate is verified against the CA **and** the hostname must match.

!!! warning "PKCS#12 client identity"
    MySQL client-certificate authentication requires the certificate and private key bundled as a
    **PKCS#12** (`.p12`) file — PEM files are not supported.

    You can create the bundle using OpenSSL:

    ```sh
    openssl pkcs12 -export \
        -in client.crt -inkey client.key \
        -out client.p12 -passout pass:secret
    ```

!!! warning "FIPS mode restriction"
    PKCS#12 client identity (`ssl-client-identity`) is **not available** in FIPS mode.
    MySQL mTLS with client certificates requires the `non-fips` feature.

## Clearing the database

The KMS server can be configured to clear the database on restart automatically.

!!! warning "Warning: this operation is irreversible"
    The cleanup operation will delete all objects and keys stored in the database.

=== "kms.toml"

    ```toml
    [db]
    clear_database = true
    ```

=== "Command line arguments"

    ```sh
    --clear-database
    ```

## Database migration

The startup migration runner supports **SQLite**, **PostgreSQL**, **MySQL**, **MariaDB**, **Percona XtraDB Cluster**, and **Redis with Findex** (non-FIPS).

Transparent migration is supported for databases created by KMS **5.20.0 or later**. An unversioned, populated SQL database is treated as `5.20.0`. Older recorded SQL versions (and Redis versions in `5.12.0..5.20.0`) trigger a warning and an attempt to run all registered steps, subject to their completion markers. Pre-5.0.0 databases and pre-5.12.0 Redis/Findex databases (either unversioned with data or recorded below `5.12.0`) require export and re-import.

The runner stores `db_version`, `db_state` and completion markers in the SQL [parameters table](tables.md#parameters); Redis uses plain keys. `db_version` records the version the runner last migrated to, not the database creation version. `db_state` is persisted as a JSON string: `"ready"` or `"upgrading"`.

On each supported backend, the server acquires a migration lock and checks the recorded version before application schema DDL. A newer database, a recorded version below the backend's minimum (`5.12.0` on Redis), or an invalid version refuses startup. Idempotent schema additions run next; data transformations run only when their release boundary satisfies `recorded < step <= target`. Release comparison uses numeric `MAJOR.MINOR.PATCH`, ignoring any `-…` or `+…` suffix. The target is the running KMS package version.

```mermaid
flowchart TD
    Start["KMS server starts"] --> Connect["Connect to database"]
    Connect --> Lock["Acquire migration lock<br/>SQLite: sidecar file<br/>PostgreSQL: advisory lock<br/>MySQL family: row lock<br/>Redis: SET NX PX lease"]
    Lock -- "held by another instance" --> Wait["Wait 500 ms and retry<br/>give up after 31 min"]
    Wait --> Lock
    Lock -- "acquired" --> ReadVersion["Read db_version without DDL"]
    ReadVersion -- "invalid version" --> Invalid["Refuse to start"]
    ReadVersion --> Compare{"Recorded version newer<br/>or below backend minimum<br/>and no clear request?"}
    Compare -- "yes" --> Refuse["Refuse before DDL"]
    Compare -- "no" --> Schema["Ensure idempotent schema<br/>Clear object data if requested"]
    Schema --> Clear{"Clear requested?"}
    Clear -- "yes" --> Stamp["Write db_version = target<br/>db_state = ready"]
    Clear -- "no" --> Recorded{"Version recorded?"}
    Recorded -- "no" --> Data{"Database holds objects?"}
    Data -- "no" --> Stamp
    Data -- "yes, SQL" --> Baseline["Treat as 5.20.0"]
    Data -- "yes, Redis" --> Legacy["Refuse unsupported legacy data<br/>Export and re-import"]
    Recorded -- "yes" --> UseRecorded["Use recorded version<br/>below 5.20.0: warn, all steps pending"]
    Baseline --> Steps
    UseRecorded --> Steps["Pending steps in ascending order<br/>Set upgrading once<br/>Skip completed markers or apply and mark<br/>Checkpoint db_version after each step"]
    Steps --> Stamp
    Stamp --> Unlock["Release migration lock"]
    Unlock --> Serve["Bind HTTP and serve requests"]
```

| Recorded `db_version` | Holds objects | Backend | Runner action |
|---|---|---|---|
| none | no | all | Stamp target version and `ready`; no data step |
| none | yes | SQL | Treat as `5.20.0`, apply pending steps unless their markers are `true`, then stamp target and `ready` |
| none or `< 5.12.0` | yes (or any when `< 5.12.0`) | Redis | Refuse unsupported pre-5.12.0 Findex data; export and re-import |
| below `5.20.0` (`>= 5.12.0` on Redis) | any | all | Warn that transparent migration is supported from `5.20.0`; offer all steps up to target, with marker checks |
| `5.20.0 <= v < target` | any | all | Apply steps with `v < step <= target`, ascending; stamp target and `ready` |
| equal to target | any | all | No step; force `ready` |
| newer than target | any | all | Refuse before schema DDL |
| any, with `db_state = upgrading` | any | all | Log the interrupted run and resume eligible steps |
| valid version or none, with `--clear-database` | wiped | all | Wipe object data under the lock, stamp target and `ready`; no data step |

Version refusals take precedence over interrupted-run recovery. `--clear-database` overrides the newer-version refusal, but an invalid version is still an error.

The runner currently registers three data steps:

- `5.15.0`: convert PostgreSQL `objects.attributes` from `json` to `jsonb`; completion marker `attributes_jsonb_converted`. This step is a no-op on SQLite, the MySQL family, and Redis.
- `5.25.0`: derive `objects.wrapping_key_id` (SQL) or `wrapped_by::<uid>` Findex keywords (Redis) from stored objects; completion marker `wrapping_key_id_backfilled`.
- `5.29.0`: add `_serial=<HEX>` lookup tags to existing certificates; completion marker `certificate_serial_tag_backfilled`.

The runner reads a step's marker before applying it, writes `true` after it succeeds, then advances the version checkpoint. Each data transformation is idempotent, so an interrupted run can resume even if it committed data before writing its marker. Version selection still applies: removing a marker alone does not rerun a step when the database is already at the target version.

A newer database is refused with this message:

```text
Database version X is newer than this KMS server version Y: refusing to start. Upgrade the KMS server to X or later.
```

### Startup locks and multiple instances

Each startup retries its backend lock every 500 ms for at most 31 minutes:

- SQLite locks the database filename followed by `.migration.lock`: for the server, `<sqlite-path>/kms.db.migration.lock`. It is an OS file lock, not a check for the file's presence. The sidecar remains after release; **do not delete it**. Closing the handle releases the lock, including on startup errors.
- PostgreSQL takes the session-level advisory lock `(1263358785, 2)` in the target database. Dropping the dedicated connection releases it.
- MySQL, MariaDB, and Percona XtraDB Cluster lock row `id = 1` in the `kms_migration_lock` table with `FOR UPDATE NOWAIT` on a dedicated connection. Disconnecting rolls back the transaction and releases the row.
- Redis sets `kms_db_migration_lock` to a random UUID v4 token with `SET ... NX PX 1800000` (30-minute lease) and releases it with a Lua compare-and-delete script.

The lock covers the version check, schema initialization, every data step and the final `ready` stamp. Other starting instances wait, then observe the completed version and apply no steps. No waiting instance binds its HTTP listener before its own bootstrap completes. SQLite instances sharing a database must also share storage that supports file locking and resolve the same database and sidecar paths.

!!! warning "Rolling upgrades do not stop older instances"
    The lock serializes startup only. It cannot stop older binaries that are already serving requests and writing to the database. Stop those instances before upgrading when writes must be quiesced; the migration state is not checked on every request.

!!! warning "Backend lock limits"
    PostgreSQL migrations require a direct connection or a PgBouncer session-pooling connection. PgBouncer transaction pooling does not preserve session-level advisory locks.

    PostgreSQL failover drops the lock session. The migration steps are idempotent, but the lock has no fencing token.

    MySQL-family row locks are local to a database server. In a multi-node Galera or Percona XtraDB Cluster deployment, start all migrating KMS instances against the same node.

    Redis migration leases (`kms_db_migration_lock`, 30 minutes) are not renewed; if a process is killed with `SIGKILL` mid-migration, delete `kms_db_migration_lock` once you have confirmed no other KMS instance is migrating, or wait for the lease to expire.

### MySQL schema update (5.14.0)

As of version 5.14.0, the MySQL schema was updated to include PRIMARY KEY constraints on the `tags` and `read_access` tables to ensure compatibility with MySQL clustering solutions (e.g., Percona XtraDB Cluster with `pxc_strict_mode=ENFORCING`, MariaDB Galera).

New installations of 5.14.0+ automatically create the corrected tables.

Existing installations upgrading to 5.14.0 will keep the old table definitions if those tables already exist. If you rely on clustering/replication that requires PRIMARY KEYs, apply the following manual migration before starting the KMS:

        -- Fix tags table
        ALTER TABLE tags
            DROP INDEX id,
            MODIFY id VARCHAR(128) NOT NULL,
            MODIFY tag VARCHAR(255) NOT NULL,
            ADD PRIMARY KEY (id, tag);

        -- Fix read_access table
        ALTER TABLE read_access
            DROP INDEX id,
            MODIFY id VARCHAR(128) NOT NULL,
            MODIFY userid VARCHAR(255) NOT NULL,
            ADD PRIMARY KEY (id, userid);

Notes:

- Run these statements using a privileged MySQL user (e.g., `root`).
- Ensure application access is paused during the migration.
- No data loss occurs; this operation converts UNIQUE constraints to PRIMARY KEYs and enforces NOT NULL.

For the operator procedure to follow when moving from 5.x to 6.0 (backup, client changes, verification), see [Upgrading from 5.x to 6.0](../../installation/upgrade_5_to_6.md).

## The Unwrapped Objects Cache

!!! info "Detailed reference"
    For the full technical reference on the KMS in-memory caches — architecture, public API, configuration options, and security trade-offs — see [Object Cache and Unwrapped Cache](../object-cache.md).

The unwrapped cache is a memory cache, and it is not persistent. The unwrapped cache is used to store unwrapped objects
that are fetched from the database.

When a wrapped object is fetched from the database, it is unwrapped and stored in the unwrapped cache.
Further calls to the same object will use the unwrapped object from the cache until the cache expires.

The time in minutes after which an unused object is evicted from the cache is configurable
using the `unwrapped_cache_max_age` setting. The default is 15 minutes.

When HSM keys wrap objects, a long expiration time will reduce the number of calls made to HSM to unwrap the object.
However, increasing the cache time will increase the memory used by the KMS server and expose the key in clear text
in the memory for a longer time.
