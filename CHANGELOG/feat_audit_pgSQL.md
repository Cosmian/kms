### PostgreSQL audit backend

- Added a `PostgreSQL` audit backend as an alternative to the JSONL file, for a
  centralized, multi-writer-safe audit trail across a fleet of KMS instances.
  Enable with `--audit-postgres-url`/`KMS_AUDIT_POSTGRES_URL` and
  `--audit-instance-id`/`KMS_AUDIT_INSTANCE_ID` (config-time backend selection,
  no runtime fallback between file and `PostgreSQL`).
- The `PostgreSQL` backend connects, acquires a session-level advisory lock
  keyed by `--audit-instance-id`, and verifies the entire existing chain
  **before** the server starts serving traffic — an unreachable database, a
  lock already held by another instance, or a broken/tampered chain aborts
  server startup, rather than silently leaving the KMS running unaudited.
- The audit database must be different from the main object-storage database
  (`--database-url`) — validated at startup.
- Schema (`kms_audit_events`, with append-only triggers rejecting `UPDATE`/
  `DELETE`/`TRUNCATE`) is created and self-healed automatically on every boot.
  A hardened deployment whose KMS role has only `INSERT`/`SELECT` rights on a
  separately-provisioned table is also supported.
- `ckms audit export`/`ckms audit verify` now accept `--audit-postgres-url`
  (with optional `--audit-instance-id`, defaulting to every instance in the
  database) as an alternative to `--path`, reading the chain in bounded pages
  rather than loading it into memory.
- Internal: generalized the audit writer/store to a common `AuditSink`
  interface shared by the file and `PostgreSQL` backends; the audit event
  schema gained a `details` field (already used by file-backend recovery
  sentinels) that now round-trips through `PostgreSQL` as well.
