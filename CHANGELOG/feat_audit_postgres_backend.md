## Features

### Audit

- The `PostgreSQL` audit backend now **always starts**, matching the file backend's always-start
  recovery policy. Startup no longer aborts on a corrupted or tampered row; recovery uses
  immutable chain **generations** instead:
  - A stable `--audit-instance-id` now owns a sequence of generations
    (`instance_id, chain_generation, id`). Exactly one generation accepts writes at a time.
  - On startup, only the latest generation is verified. Content corruption there — a row whose
    own hash doesn't match its bytes, a row that doesn't chain to its predecessor, an
    unparsable column, or a valid tail at the id counter's limit — is classified by cause and
    **seals** the generation unchanged, as forensic evidence, before starting a fresh one.
  - The new generation begins with a row-0 `audit:reanchor` event recording the sealed and new
    generation numbers, the first failing id, the reason, and a SHA-256 evidence digest computed
    over a deterministic SQL projection of the sealed generation — independently reproducible
    with `psql` piped to `sha256sum`, without trusting the KMS's own hashing.
  - Connectivity, TLS, schema, advisory-lock, and recovery-write failures are unchanged and
    still abort startup — only content corruption is now recovered.
- The file backend's interior-scan classification is refined: a row that verifies on its own but
  doesn't chain to its predecessor is now reported as `broken_link` instead of `hash_mismatch`,
  matching the more precise vocabulary the `PostgreSQL` backend also uses.
- The file audit backend now records a final `audit:size-cap-reached` event before stopping at its
  configured size limit.
- The `PostgreSQL` audit connection now honors `sslmode=verify-ca`/`verify-full` (plus
  `sslrootcert`/`sslcert`/`sslkey`) the same way the main database connection does. Previously
  any non-`disable` `sslmode` silently skipped certificate verification.
- When the `PostgreSQL` audit role has no DDL rights (hardened deployment), startup now also
  verifies that the four append-only guard triggers on `kms_audit_events` exist and are enabled,
  and refuses to start otherwise, instead of trusting the pre-provisioned schema.
- Upgrading from 5.28.0 needs no migration: the object-store schema is unchanged, the
  `PostgreSQL` audit tables are new and created on first connection, file audit logs keep the same
  hash-chain format and resume in place, and every new configuration key is optional.

## Testing

### Audit

- `mise run test:audit` now also runs the live `PostgreSQL` audit suite (`test:audit-postgres`).
  It covers resume after a roll, consecutive rolls, the `unparsable` and `id_overflow` reasons, the
  restricted `kms_audit_writer` role (self-provisioned by the tests), and an end-to-end
  tamper → restart → seal-and-roll → `ckms audit verify` scenario against a real server.
