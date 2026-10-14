# PostgreSQL backend

Use the PostgreSQL backend for a centralized, multi-writer-safe audit trail across a fleet of
KMS instances. Each instance still owns its own hash chain, scoped by an instance ID, but every
chain lives in one shared, append-only database that every instance, and every auditor, can read.

---

## Prerequisites

Requires PostgreSQL 11 or later: earlier versions are missing a hash function the KMS uses to key
its per-instance advisory lock, and the server fails to start against them with a clear SQL error.
We recommend PostgreSQL 14 or later, since older versions are no longer maintained upstream.
Cosmian tests against and recommends PostgreSQL 18, the current release.

The audit database must be different from the main object-storage database (`--database-url`):
the server checks this at startup (comparing host, port, and database name) and refuses to start
otherwise. Sharing one database would let the KMS's own object-store role bypass the audit
database's append-only grants.

`--audit-postgres-url` supports the same `sslmode`/`sslrootcert`/`sslcert`/`sslkey` query
parameters as `--database-url`; see [PostgreSQL TLS / mTLS](./database/configuration.md#postgresql-tls-mtls).

The KMS creates its table on first connection, with triggers that reject `UPDATE`, `DELETE`, and
`TRUNCATE` on it. The table owner and any superuser can still disable these triggers with
`ALTER TABLE … DISABLE TRIGGER`, so run the KMS with a role that does not own the table (see
below) and rely on the hash chain, verified by `ckms audit verify`, to detect tampering by a
privileged role. This runs again on every boot and self-heals an older table automatically.

For a hardened deployment, a database administrator can provision both tables separately and grant
the KMS role only `SELECT` and `INSERT` on `kms_audit_events`, plus `SELECT`, `INSERT`, and `UPDATE` on
`kms_audit_control`, with no DDL rights; see
[the exact schema](https://github.com/Cosmian/kms/blob/develop/crate/server_database/src/stores/audit/audit.sql).
The KMS then skips schema creation and only checks that every required column is present and that
the four append-only triggers (`kms_audit_no_update`, `kms_audit_no_delete`,
`kms_audit_no_truncate`, `kms_audit_no_insert_sealed`) exist and are enabled; it refuses to start
otherwise. Grants are not checked and remain the administrator's responsibility.

---

## Configuration

=== "TOML configuration file"

    ```toml
    [audit]
    enabled = true

    [audit.postgres]
    url = "postgresql://kms_audit:password@db-host:5432/kms_audit"
    instance_id = "kms-eu-west-1a"
    ```

=== "Command line"

    ```bash
    cosmian_kms --audit-enable \
      --audit-postgres-url postgresql://kms_audit:password@db-host:5432/kms_audit \
      --audit-instance-id kms-eu-west-1a
    ```

=== "Environment variables"

    ```bash
    export KMS_AUDIT_ENABLE=true
    export KMS_AUDIT_POSTGRES_URL=postgresql://kms_audit:password@db-host:5432/kms_audit
    export KMS_AUDIT_INSTANCE_ID=kms-eu-west-1a
    cosmian_kms
    ```

| CLI flag               | Environment variable     | Required | Description                                                                                |
| ---------------------- | ------------------------ | -------- | ------------------------------------------------------------------------------------------ |
| `--audit-postgres-url` | `KMS_AUDIT_POSTGRES_URL` | Yes      | Connection URL for the audit database.                                                     |
| `--audit-instance-id`  | `KMS_AUDIT_INSTANCE_ID`  | Yes      | Identifies this instance's chain. See [Choosing an instance ID](#choosing-an-instance-id). |

These settings are specific to the PostgreSQL backend. For the settings shared with the file
backend (channel capacity, failure mode, trusted proxies), see
[Audit logging](./audit-logs.md#configuration).

Setting `--audit-postgres-url` selects the PostgreSQL backend instead of the file backend, at
configuration time, with no fallback between the two. If `--audit-file-path` is also set, it is
never used: the KMS logs a warning and ignores it.

---

## Choosing an instance ID

The instance ID must be stable across restarts and unique among every KMS instance sharing the
same database: 1 to 255 characters, with no default. A Kubernetes deployment should set it
explicitly, for example from the `StatefulSet` ordinal, rather than rely on an ephemeral pod
hostname.

The server enforces uniqueness with a session-level advisory lock keyed by the instance ID, held
for as long as it runs. A second instance configured with the same ID fails to start.

---

## Startup and recovery

The PostgreSQL backend verifies its chain before the KMS starts serving traffic, unlike the file
backend, which always starts immediately and recovers in the background. The KMS refuses to
start if the database is unreachable, if another instance already holds the instance ID's lock,
or if the table cannot be created or validated.

Content corruption does not block startup. A stable instance ID owns a sequence of chain
generations, numbered from 0; only one generation accepts writes at a time, and older generations
are never modified again. On startup, the KMS verifies the latest generation. If a row is found
corrupted, that generation is sealed as-is and a fresh one starts with a row-0 `audit:reanchor`
event. The `reason` field classifies the cause (see
[Reanchor reasons](./audit-events.md#reanchor-reasons)).

The reanchor event's `details` also record which generation was sealed and a digest of the
sealed generation's content:

```json
{
  "sealed_generation": 0,
  "new_generation": 1,
  "first_failure_id": 2,
  "reason": "hash_mismatch",
  "evidence": "v1:sha256:<64 hex chars>"
}
```

This is logged as an error; monitor for it the same way you would for a file-backend
seal-and-roll (see [Audit events](./audit-events.md#system-events) and the
[log reference](./log-reference.md)).

---

## Verifying and exporting

`ckms audit verify` and `ckms audit export` accept `--audit-postgres-url` as an alternative to
`--path`. Omit `--audit-instance-id` to cover every instance in the database:

```bash
ckms audit verify --audit-postgres-url postgresql://kms_audit:password@db-host:5432/kms_audit
```

```text
== instance_id: kms-eu-west-1a ==
instance_id=kms-eu-west-1a: chain OK: 128 events verified
== instance_id: kms-eu-west-1b ==
instance_id=kms-eu-west-1b: chain OK: 96 events verified
```

`verify` checks every row's hash and its link to the previous row, one generation at a time.
A failing generation or instance does not stop the rest from being checked: a generation sealed by
a recovery stays failed, so the report lists every failing generation together with the ones that
verified clean, and the command exits with code 1 if any failed.
It does not yet check a reanchor's recorded evidence digest against the sealed generation's
current content; reproduce that check manually (see below).

`ckms audit export` prints events in the shape described in [Audit events](./audit-events.md#fields),
plus `instance_id` and `chain_generation`. With `--format cef` it produces [CEF](./cef-export.md),
identifying each event by its instance and generation. See [ckms audit](../kms_clients/audit.md)
for the full CLI reference.

---

## Checking sealed evidence by hand

The `evidence` digest is a SHA-256 hash over a deterministic SQL projection of every row in the
sealed generation, in `id` order, plus a footer recording the generation number and row count.
Reproduce it directly against the database, without trusting the KMS's own hashing:

```bash
QUERY="SELECT 'v1' || '|' || encode(convert_to(instance_id, 'UTF8'), 'hex') || '|' ||
  chain_generation || '|' || id || '|' ||
  to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') || '|' ||
  encode(convert_to(operation, 'UTF8'), 'hex') || '|' ||
  encode(convert_to(username, 'UTF8'), 'hex') || '|' ||
  COALESCE(encode(convert_to(object_uid, 'UTF8'), 'hex'), '-') || '|' ||
  COALESCE(encode(convert_to(algorithm, 'UTF8'), 'hex'), '-') || '|' ||
  COALESCE(encode(convert_to(client_ip, 'UTF8'), 'hex'), '-') || '|' ||
  encode(convert_to(result, 'UTF8'), 'hex') || '|' || duration_ms || '|' ||
  COALESCE(request_id::text, '-') || '|' ||
  COALESCE(encode(convert_to(details, 'UTF8'), 'hex'), '-') || '|' ||
  encode(prev_hash, 'hex') || '|' || encode(row_hash, 'hex')
  FROM kms_audit_events
  WHERE instance_id = '<instance_id>' AND chain_generation = <sealed_generation>
  ORDER BY id ASC"

{
  psql "$KMS_AUDIT_POSTGRES_URL" -qtA -c "$QUERY"
  printf 'v1|end|%s|%s\n' "<sealed_generation>" "<row_count>"
} | sha256sum
```

The resulting hex digest, prefixed with `v1:sha256:`, must match the `evidence` field recorded
in the corresponding `audit:reanchor` event.
