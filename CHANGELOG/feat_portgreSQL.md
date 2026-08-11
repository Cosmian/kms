## Features

### PostgreSQL audit backend

Cosmian KMS's tamper-evident audit trail can now be written to a `PostgreSQL`
database instead of (or as an alternative to) the local JSONL file.

**Configuration**

```toml
[audit]
enabled = true

[audit.postgres]
url = "postgresql://kms_audit:secret@db:5432/kms_audit?sslmode=verify-full"
instance_id = "kms-eu-west-1a"   # defaults to the machine hostname
```

`--audit-postgres-url` / `KMS_AUDIT_POSTGRES_URL` and `--audit-instance-id` /
`KMS_AUDIT_INSTANCE_ID` are the equivalent CLI flags. The audit database MUST
be different from the main object-storage database (`--database-url`); the
server refuses to start otherwise.

**Per-instance chains, enforced by the schema**

Each KMS instance owns an independent hash chain, restarting at `id = 0`. The
composite primary key `(instance_id, id)` makes a chain fork **impossible**,
not just detected: two KMS instances writing under the same `instance_id`
collide on `INSERT` (`SQLSTATE 23505`) and the second one refuses to continue,
with a message naming the conflicting `instance_id`.

**Append-only, defence in depth**

The `kms_audit_events` table is protected by three independent layers: a
`REVOKE UPDATE, DELETE, TRUNCATE ... FROM PUBLIC`, `BEFORE UPDATE`/`DELETE`
triggers that reject any mutation (including from the table owner), and the
SHA-256 hash chain itself, which is the only layer that survives a privileged
administrator with `DISABLE TRIGGER` access. See
`documentation/docs/adr/0006-postgresql-audit-backend.md` for the exact
guarantee this backend provides (and does not provide).

**Fail-fast, not silent fallback**

Backend selection is config-time only. An unreachable `PostgreSQL` audit
database at startup, or a runtime write failure that survives its own retry
budget, both stop the server rather than silently falling back to no audit
logging.

**`ckms audit` against `PostgreSQL`**

Both `ckms audit export` and `ckms audit verify` gained `--postgres-url` and
`--instance-id`, alongside the existing `--path` (JSONL file) option. Exactly
one source must be supplied; omitting `--instance-id` processes every chain in
the database in turn, reporting one summary line per chain.

### Internal refactors accompanying this change

- The audit writer/channel handle (`AuditStore`), the writer task
  (`core::audit::writer`), and the JSONL sink (`core::audit::file_sink`) are
  now separate modules behind a shared `cosmian_kms_interfaces::AuditSink`
  trait, so a third backend is a new file rather than a refactor.
- `AuditEventDraft` now has a single constructor
  (`AuditEventDraft::build(RequestAuditContext, OperationAuditContext,
  AuditResult)`), replacing three separate call sites that previously
  duplicated the field list.
- Audit timestamps are truncated to microsecond resolution at draft time
  (`cosmian_kms_access::audit::audit_now()`), matching `PostgreSQL`
  `TIMESTAMPTZ` precision so a chain's `row_hash` is re-derivable from either
  backend's stored columns.
- `crate/server_database`'s `PostgreSQL` connection-pool and retry-backoff
  logic is now shared (`stores::sql::{pg_pool, pg_retry}`) between the object
  store and the new audit backend.
