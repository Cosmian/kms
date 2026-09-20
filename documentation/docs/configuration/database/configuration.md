# Databases

By default, the server runs using a [SQLite](https://www.sqlite.org/) database, but it can be configured to use a choice
of databases: SQLite encrypted, [PostgreSQL](https://www.postgresql.org/), [MariaDB](https://mariadb.org/),
[MySQL](https://www.mysql.com/), and [Percona XtraDB Cluster](https://www.percona.com/software/mysql-database/percona-xtradb-cluster),
as well as [Redis](https://redis.io/), using the [Redis-with-Findex](#redis-with-findex) configuration.

## Selecting the database

All databases, except SQLite, can be used in a high-availability setup.

The **SQLite** database can serve high loads and millions of objects, and is very suitable
for scenarios that do not demand high availability.

### Redis with Findex

Redis-with-Findex provides application-level encryption over Redis, combining AES-256-GCM encrypted objects with
encrypted Findex indexes. See the dedicated [Redis with Findex](./redis.md) page for a full description,
encryption details, and configuration reference.

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

#### PostgreSQL

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

##### PostgreSQL High-Availability (multi-host)

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

##### Replication and standby writability

!!! warning "A standby is read-only"
    In standard PostgreSQL streaming replication, the standby node operates in **hot standby
    mode**: it accepts read queries but **rejects all writes**. The KMS requires a read-write
    connection for every operation, so `target_session_attrs=read-write` will skip a standby
    automatically — but this also means **the KMS cannot use the standby as a fallback by
    itself**. The standby only becomes usable by the KMS after it has been **promoted** to
    primary.

    Replication is entirely managed by the PostgreSQL infrastructure — the KMS does not
    configure, trigger, or monitor it.

###### Recommended setup: use an HA manager

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

##### PostgreSQL failover retry

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

##### Multi-region active-active PostgreSQL (Spock / pgEdge / BDR)

The KMS supports multi-region active-active deployments using PostgreSQL with a Spock-, pgEdge-, or BDR-class logical multi-master replication extension (validated against `ghcr.io/pgedge/pgedge-postgres`). In this topology, each region runs a local KMS instance group connected to a local PostgreSQL node, serving local reads and writes for minimum latency. State converges asynchronously across regions via bidirectional logical replication.

KMS server nodes do not communicate directly with each other over the network. All cross-region state coordination and replication are handled entirely at the database layer:

```mermaid
graph TD
    subgraph Region A [Region A - Leader]
        ClientA[Client / App] --> KMSA[KMS Server Node<br/>--region-role leader]
        KMSA --> PGA[(PostgreSQL Node A)]
    end

    subgraph Region B [Region B - Follower]
        ClientB[Client / App] --> KMSB[KMS Server Node<br/>--region-role follower]
        KMSB --> PGB[(PostgreSQL Node B)]
    end

    subgraph Region C [Region C - Follower]
        ClientC[Client / App] --> KMSC[KMS Server Node<br/>--region-role follower]
        KMSC --> PGC[(PostgreSQL Node C)]
    end

    PGA <-->|Logical Multi-Master Replication<br/>Spock / pgEdge full-mesh| PGB
    PGB <-->|Logical Multi-Master Replication| PGC
    PGA <-->|Logical Multi-Master Replication| PGC
```

###### Topology and `region_role`

To prevent split-brain conflicts on operations requiring global coordination, the deployment defines a topological role per region via the `region_role` configuration setting:

```toml
# /etc/cosmian/kms.toml
region_role = "leader"    # exactly one region per deployment
# region_role = "follower"  # all other regions
```

Or via CLI flag `--region-role <leader|follower>` or environment variable `KMS_REGION_ROLE`.

###### Leader-only operations

Exactly one region across the entire deployment MUST be designated `leader` (`region_role = "leader"`, which is the default). All other regions MUST be configured as `follower`.

The `leader` region is the only region permitted to execute:

1. **X.509 CRL generation and background refresh** — RFC 5280 §5.2.3 requires strict per-issuer `crlNumber` monotonicity. Concurrent issuance from uncoordinated writers violates this requirement.
2. **Crypto Officer ceremony activation and revocation** — Key ceremonies rely on dual-control quorum and activation history; safety takes priority over local write availability.

If a client attempts CRL generation or ceremony activation/revocation against a node configured with `region_role = "follower"`, the request is rejected immediately with an HTTP 422 error instructing the client to target the leader region. Background CRL refresh cron tasks on followers are automatically skipped.

###### CRL endpoints across regions

The KMS exposes two distinct CRL endpoints:

1. **Authenticated generation endpoint** (`GET /certificates/{issuer_id}/crl`):
   Signs a fresh X.509 v2 CRL using the CA private key, assigns a new monotonically increasing `crlNumber`, writes the signed CRL to the `crls` table, and updates the in-memory cache.
   - **Leader-gated**: Must only be executed on the `leader` region (`require_leader_region`). Calling this on a `follower` region returns HTTP 422 (`KmsError::InvalidRequest`).
   - **Background refresh cron**: The periodic background task (`crl_refresh_check_hours`) is automatically executed only on the `leader` region; followers skip the check.
   - **Revocation auto-trigger**: A certificate revocation on the `leader` region triggers automatic CRL regeneration.

2. **Public distribution endpoint (CDP)** (`GET /public/certificates/{issuer_id}/crl`):
   Unauthenticated public endpoint serving pre-signed CRL bytes to relying parties (browsers, TLS clients, validators).
   - **Active on every region**: Runs locally on all nodes (both `leader` and `follower`).
   - **Replicated data**: The `crls` table is included in the replication set. When the leader generates and persists a new CRL, the row (`issuer_id`, `crl_der`, `crl_number`, `generated_at`, `next_update`) replicates asynchronously to all follower PostgreSQL databases.
   - **Serving from cache and DB**: When a client requests the public CDP on a follower region, the follower serves it from its local in-memory cache, or falls back to reading the replicated row in its local `crls` table on cold start or cache refresh.

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant KMS_A as KMS Region A (Leader)
    participant DB_A as PostgreSQL A
    participant DB_B as PostgreSQL B
    participant KMS_B as KMS Region B (Follower)
    actor Client as Relying Party (TLS Client)

    Note over Admin,KMS_A: CRL Generation (Leader only)
    Admin->>KMS_A: GET /certificates/{issuer_id}/crl (Authenticated)
    Note over KMS_A: Sign CRL with CA key (crlNumber N+1)
    KMS_A->>DB_A: UPSERT INTO crls (issuer_id, crl_der, crl_number, next_update)
    KMS_A-->>Admin: 200 OK (Signed CRL)

    DB_A-->>DB_B: Asynchronous replication of crls table (Spock)

    Note over Client,KMS_B: Public CDP Distribution (Any region)
    Client->>KMS_B: GET /public/certificates/{issuer_id}/crl (Unauthenticated)
    alt In-memory cache hit
        Note over KMS_B: Serve from memory
    else Cold start / cache miss
        KMS_B->>DB_B: SELECT crl_der, next_update FROM crls WHERE issuer_id = ...
        DB_B-->>KMS_B: Replicated CRL row
        Note over KMS_B: Populate in-memory cache
    end
    KMS_B-->>Client: 200 OK (application/pkix-crl)

    Note over Admin,KMS_B: Attempted Generation on Follower
    Admin->>KMS_B: GET /certificates/{issuer_id}/crl
    KMS_B-->>Admin: 422 Unprocessable Entity (target leader region)
```

Every other operation (key generation, encryption, decryption, access grants, Locate, etc.) executes locally on any region with no leader dependency.

```mermaid
sequenceDiagram
    autonumber
    actor Alice
    participant KMS_A as KMS Region A (Leader)
    participant DB_A as PostgreSQL A
    participant DB_B as PostgreSQL B
    participant KMS_B as KMS Region B (Follower)
    actor Bob

    Note over Alice,KMS_A: Local Object Operation (Region A)
    Alice->>KMS_A: POST /kmip/2_1 (Create AES Key)
    KMS_A->>DB_A: INSERT INTO objects ... (State: PreActive/Active)
    KMS_A-->>Alice: 200 OK (Key UID)
    DB_A-->>DB_B: Asynchronous Logical Replication (Spock)

    Note over Bob,KMS_B: Local Crypto Operation on Follower
    Bob->>KMS_B: POST /kmip/2_1 (Encrypt with Key UID)
    KMS_B->>DB_B: SELECT FROM objects WHERE uid = ...
    DB_B-->>KMS_B: Object found (replicated)
    KMS_B-->>Bob: 200 OK (Ciphertext)
```

###### State conflict resolution (monotonic merge)

In multi-region active-active replication, object `State` transitions can race across regions (e.g. an object deactivated in region A while destroyed in region B). Standard commit-timestamp last-write-wins (LWW) could silently overwrite a terminal `Destroyed` or `Compromised` state with an earlier `Deactivated` write.

The KMS installs an automatic `BEFORE UPDATE` trigger on the `objects` table marked `ENABLE ALWAYS`, so it coerces **every** state update — both local writes and incoming replicated writes — to `GREATEST(existing_state, incoming_state)` using the NIST SP 800-57 / KMIP lifecycle hierarchy:

$$\text{PreActive (1)} < \text{Active (2)} < \text{Deactivated (3)} < \text{Compromised (4)} < \text{Destroyed (5)} < \text{Destroyed\_Compromised (6)}$$

`ENABLE ALWAYS` (rather than the default `ENABLE`/origin-only, or `ENABLE REPLICA`) is required because a local write on one region can otherwise race against a state that has *already replicated in* from another region at a higher rank: e.g. region B receives `Destroyed` from region A, then a stale local `Deactivated` write on region B — issued under the ordinary `session_replication_role = 'origin'` — must still be coerced back to `Destroyed`.

The one legitimate backward transition — KMIP batch UNDO reverting an object to `PreActive` (`message.rs::revert_activation_to_preactive`) — bypasses the guard via a transaction-scoped `SET LOCAL kms.allow_backward_state_transition = 'on'`, set only by that revert path.

###### Permissions and access control (LWW)

Concurrent conflicting modifications to `read_access` (e.g. concurrent grant on node 1 and revoke on node 2 for the same `(object_id, user_id)` pair) converge via the underlying replication extension's row-level conflict resolution (`last_update_wins`). A concurrent grant and revoke on the same object/user pair can result in either state winning.

###### Crypto Officer ceremony across regions

`crypto_officer_activations` replicates like any other table in the default replication set: a Crypto Officer ceremony completed on the leader region becomes recognized on every follower region automatically, once the activation row replicates (subject to ordinary replication lag — there is no separate per-region CO status). The same applies to revocation.

This requires every region's KMS server to be configured with the **identical** `ceremony_secret` (or a `ceremony_key_id` resolving to the same underlying key). Ceremony records are AES-256-GCM sealed with keys derived from this value; a follower configured with a different secret cannot verify replicated records — it fails secure (treats the user as not an active Crypto Officer, logging a warning) rather than erroring, but the ceremony will not be usable on that region until the secret is corrected to match the leader.

```mermaid
sequenceDiagram
    autonumber
    actor Alice
    participant KMS_A as KMS Region A (Leader)
    participant DB_A as PostgreSQL A
    participant DB_B as PostgreSQL B
    participant KMS_B as KMS Region B (Follower)

    Note over Alice,KMS_A: Leader Region Ceremony Activation
    Alice->>KMS_A: POST /access/crypto_officer/ceremony/activate (Shares)
    Note over KMS_A: Validate shares & reconstruct master key
    Note over KMS_A: AES-256-GCM seal record using local CeremonyKeys
    KMS_A->>DB_A: INSERT INTO crypto_officer_activations (user_id, sealed_record)
    KMS_A-->>Alice: 200 OK (Alice is active CO in Region A)

    DB_A-->>DB_B: Replicate crypto_officer_activations row (Spock)

    Note over Alice,KMS_B: Role Evaluation on Follower Region
    Alice->>KMS_B: GET /kmip/2_1 (Locate / Export / CO-gated operation)
    KMS_B->>DB_B: SELECT sealed_record FROM crypto_officer_activations WHERE user_id = Alice
    DB_B-->>KMS_B: sealed_record
    Note over KMS_B: Unseal sealed_record using Region B CeremonyKeys

    alt ceremony_secret identical across regions
        Note over KMS_B: GCM tag verified successfully
        KMS_B-->>Alice: Authorized as Crypto Officer
    else ceremony_secret differs (Misconfiguration)
        Note over KMS_B: GCM tag verification fails -> Fails Secure (warn log)
        KMS_B-->>Alice: Treated as Operator (Not CO)
    end
```

###### Extension requirements

Any PostgreSQL multi-master extension supporting Spock/BDR/pglogical protocols is supported. Key requirements:

- `wal_level = logical`
- `track_commit_timestamp = on`
- Shared replication set covering all public KMS tables (`objects`, `tags`, `read_access`, `crypto_officer_activations`, `parameters`, `crls`).

#### MySQL, MariaDB, or Percona XtraDB Cluster

The KMS supports MySQL-compatible databases including MySQL, MariaDB, and Percona XtraDB Cluster.
All use the same configuration with `database-type=mysql`.

!!! note Clustering Support
    As of version 5.13.0, the KMS schema includes PRIMARY KEY constraints on all tables,
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

!!!info "Using a certificate to authenticate to MySQL or MariaDB"

        Use a certificate to authenticate to MySQL or MariaDB with the `mysql-user-cert-file` option to
        specify the certificate file name.

        **Example context**: say the certificate is called `cert.p12`
        and is in a directory called `/certificate` on the host disk.

=== "Docker"

    ```sh
    docker run --rm -p 9998:9998 \
        --name kms ghcr.io/cosmian/kms:latest \
        -v /certificate/cert.p12:/root/cosmian-kms/cert.p12 \
        --database-type=mysql \
        --database-url=mysql://mysql_server:3306/kms \
        --mysql-user-cert-file=cert.p12
    ```

=== "kms.toml"

    ```toml
    [db]
    database_type = "mysql"
    database_url = "mysql://mysql_server:3306/kms"
    # Note: if client certificate authentication is required for MySQL,
    # configure it via command-line option `--mysql-user-cert-file` for now.
    # A dedicated TOML key may not be available in this version.
    ```

#### Redis with Findex

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

| Parameter     | Description                                                                    |
| ------------- | ------------------------------------------------------------------------------ |
| `sslmode`     | TLS mode: `disable`, `prefer` (default), `require`, `verify-ca`, `verify-full` |
| `sslrootcert` | Path to the CA certificate (PEM) used to verify the server                     |
| `sslcert`     | Path to the client certificate (PEM) for mTLS                                  |
| `sslkey`      | Path to the client private key (PEM) for mTLS                                  |

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
    - `prefer` (default) / `require` – TLS is used but the server certificate is **not** verified.
    - `verify-ca` – the server certificate is verified against the CA but the hostname is **not** checked.
    - `verify-full` – the server certificate is verified against the CA **and** the hostname must match.

    All certificates must be in **PEM** format.

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

Depending on the KMS database evolution, a migration can happen between 2 versions of the KMS server. It will be clearly
written in the CHANGELOG.md. In that case, a generic database upgrade mechanism is run on startup.

At first, the table `context` is responsible for storing the software run's version and the database's state.
The state can be one of the following:

- `ready`: the database is ready to be used
- `upgrading`: the database is being upgraded

On startup, the server checks if the software version is greater than the last version run:

- if no, it simply starts;
- If yes:

    - it looks for all upgrades to apply in order from the last version run to this version;
    - if there is any to run, it sets an upgrading flag on the db state field in the context table;
    - it runs all the upgrades in order.
    - it sets the flag from upgrading to ready;

On every call to the database, a check is performed on the db state field to check if the database is upgrading. If yes,
calls fail.

Upgrades resist being interrupted in the middle and resumed from the start if that happens.

### MySQL schema update (5.13.0)

As of version 5.13.0, the MySQL schema was updated to include PRIMARY KEY constraints on the `tags` and `read_access` tables to ensure compatibility with MySQL clustering solutions (e.g., Percona XtraDB Cluster with `pxc_strict_mode=ENFORCING`, MariaDB Galera).

New installations of 5.13.0+ automatically create the corrected tables.

Existing installations upgrading to 5.13.0 will keep the old table definitions if those tables already exist. If you rely on clustering/replication that requires PRIMARY KEYs, apply the following manual migration before starting the KMS:

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
