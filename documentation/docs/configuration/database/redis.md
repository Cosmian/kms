# Redis with Findex

The KMS can store its entire database in [Redis](https://redis.io/) using the **Redis-with-Findex** backend.
Redis-with-Findex combines application-level encryption with encrypted, searchable indexes, so the KMS can query encrypted data without revealing it to the Redis server.

!!! warning "Non-FIPS only"
    Redis-with-Findex is gated behind the `non-fips` feature and is **not available in FIPS mode**.

## What it is

With Redis-with-Findex, the KMS server encrypts all data before sending it to Redis:

- **Objects and permissions** are encrypted with AES-256-GCM using a key derived from a master password.
- **Indexes** are built with [Findex](https://github.com/Cosmian/findex/), an Eviden cryptographic algorithm that produces encrypted indexes over encrypted data.
  The indexes are also stored in Redis, allowing fast encrypted queries (for example `Locate` by tag or attribute) without the KMS ever sending plaintext to Redis.

Redis-with-Findex provides post-quantum resistance on both the encrypted data and the encrypted indexes.

## When to use it

Redis-with-Findex is most useful when:

- The KMS servers run inside a **confidential VM or an enclave**.
  In this case the secret used to encrypt the Redis data and indexes is protected by the VM or enclave and cannot be recovered at runtime by inspecting the KMS servers' memory.
- The KMS servers are run by a **trusted party**, but the Redis backend is managed by an **untrusted third party**.

It is the database selected to [run the Eviden KMS in the cloud or any other zero-trust environment](../../installation/marketplace_guide.md).

## How encryption keys are derived

1. A **master password** is provided at startup (`redis_master_password`).
2. A 32-byte **master key** is derived from the password using **Argon2** (salt `rediswithfindex_`).
3. A **database key** is derived from the master key (salt `db`) and is used to encrypt the object and permission data with AES-256-GCM.
4. The master key is also used by the Findex encryption layer to encrypt the searchable indexes.

The master password never leaves the KMS server; only the derived keys are used in memory.

## Data layout in Redis

Redis-with-Findex does not use relational tables (see [Database tables](./tables.md) for the SQL schema).
Instead it stores:

| Data | Storage |
| ---- | ------- |
| Objects | AES-256-GCM encrypted values, keyed by object UID |
| Permissions | Encrypted, indexed through Findex |
| Searchable indexes | Findex encrypted indexes (Redis is used as the Findex memory layer) |
| Database metadata | Internal keys holding the database state (`ready`/`upgrading`) and version |
| Ceremony records | Encrypted records under key names obfuscated with the master key |

## Configuration

Redis-with-Findex requires the database URL and a master password:

=== "kms.toml"

    ```toml
    [db]
    database_type = "redis-findex"
    database_url = "redis://localhost:6379"
    redis_master_password = "password"
    ```

=== "Command line arguments"

    ```sh
    --database-type=redis-findex \
    --database-url=redis://localhost:6379 \
    --redis-master-password=password
    ```

The corresponding environment variables are `KMS_DATABASE_TYPE`, `KMS_DATABASE_URL` (also `KMS_REDIS_URL`), and `KMS_REDIS_MASTER_PASSWORD`.

For the full database configuration reference, including TLS, clearing, and migration, see [Databases](./configuration.md).

!!! note "Clearing the database"
    When `clear_database` is set, the KMS issues a `FLUSHDB` to Redis on startup, deleting all keys in the selected Redis database.

## Migration

Redis-with-Findex databases created by older KMS versions carry their version and state markers in Redis.
Support for migrating **legacy** Redis/Findex databases has been removed: if a database is detected without a `ready` state and a version marker, the KMS refuses to start and asks you to export the data from the legacy KMS and re-import it into the current version.
