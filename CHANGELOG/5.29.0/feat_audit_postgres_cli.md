### PostgreSQL audit backend

- Added a `PostgreSQL` audit backend as an alternative to the JSONL file, for a
  centralized, multi-writer-safe audit trail across a fleet of KMS instances.
  Enable with `--audit-postgres-url`/`KMS_AUDIT_POSTGRES_URL` and
  `--audit-instance-id`/`KMS_AUDIT_INSTANCE_ID` (config-time backend selection,
  no runtime fallback between file and `PostgreSQL`).
- The `PostgreSQL` backend connects, acquires a session-level advisory lock
  keyed by `--audit-instance-id`, and verifies the entire existing chain
  **before** the server starts serving traffic. An unreachable database or a
  lock already held by another instance still aborts server startup; content
  corruption (a tampered or malformed row) no longer does — the corrupted
  chain generation is sealed as evidence and a fresh one starts automatically.
- The audit database must be different from the main object-storage database
  (`--database-url`) — validated at startup.
- Schema (`kms_audit_events`, with append-only triggers rejecting `UPDATE`/
  `DELETE`/`TRUNCATE`) is created and self-healed automatically on every boot.
  A hardened deployment with separately-provisioned tables is also supported:
  the KMS role then needs only `SELECT`/`INSERT` on `kms_audit_events` and
  `SELECT`/`INSERT`/`UPDATE` on `kms_audit_control`, with no DDL rights.
- `ckms audit export`/`ckms audit verify` now accept `--audit-postgres-url`
  (with optional `--audit-instance-id`, defaulting to every instance in the
  database) as an alternative to `--path`, reading the chain in bounded pages
  rather than loading it into memory. Each instance's chain generations
  (see the seal-and-roll recovery entry) are read and verified independently,
  in order — a generation is never treated as a continuation of the one before it.
- Internal: generalized the audit writer/store to a common `AuditSink`
  interface shared by the file and `PostgreSQL` backends; the audit event
  schema gained a `details` field (already used by file-backend recovery
  sentinels) that now round-trips through `PostgreSQL` as well.

### PostgreSQL audit backend — fixes and test hardening

- Fixed: the seal-and-roll recovery write (advancing the active generation and
  inserting the `audit:reanchor` event) is now atomic. A failure between the
  two steps could previously leave the control row pointing at a generation
  with no reanchor event.
- Fixed: `ckms audit verify --audit-postgres-url ... --audit-instance-id <id>`
  now fails with a clear error when `<id>` has no events, instead of reporting
  a vacuously verified empty chain.
- Fixed: the dedicated `test:audit-postgres` CI job now runs the `PostgreSQL`
  audit test suite (it previously only ran on a pre-populated schema, so a
  first-time/clean run failed).
- Fixed: several KMS instances connecting to the same audit database at the
  same moment (fresh database or rolling restart) no longer fail to start. The
  schema bootstrap re-applied on every connection now runs in one transaction,
  serialized across instances, so the append-only triggers are also never
  briefly absent while it runs.
- Fixed: `ckms audit verify --audit-postgres-url` now checks every chain
  generation of every instance instead of stopping at the first failure. After
  a seal-and-roll recovery, the sealed generation still fails verification, but
  the active generation is verified too and reported as clean or failed.

### Documentation

- Reorganized the Audit & SIEM docs: a shared overview with a backend
  comparison, dedicated file backend and `PostgreSQL` backend pages, and a
  new audit events reference (fields, system events, hash chain) that the
  CEF export and SIEM integration pages now link to instead of duplicating.
  Corrected several inaccuracies along the way (the `--audit-instance-id`
  default, the CEF version reference, and stale wording that predated the
  `PostgreSQL` backend).
- Document CEF export for both audit storage backends, with PostgreSQL examples
  and source fields.
- Document read-only collection accounts for the audit file and PostgreSQL database.

## Bug Fixes

### CLI

- Reject `--audit-instance-id` when a file source is used by `ckms audit export` or `ckms audit verify`.
- Continue PostgreSQL audit verification after row-decoding errors.
- Include instance and chain generation in PostgreSQL JSON and CEF audit exports.
- `ckms audit export` fails on an `--audit-instance-id` with no events, like `verify`.
- `ckms audit` no longer reads `KMS_AUDIT_INSTANCE_ID`. `KMS_AUDIT_FILE_PATH` and
  `KMS_AUDIT_POSTGRES_URL` are only used when no source option is given.
