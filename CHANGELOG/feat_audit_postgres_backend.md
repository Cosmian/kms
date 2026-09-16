## Features

### Audit

- The `PostgreSQL` audit backend now **always starts**, matching the file backend's always-start
  recovery policy. Startup no longer aborts on a corrupted or tampered row; recovery uses
  immutable chain **generations** instead:
  - A stable `--audit-instance-id` now owns a sequence of generations
    (`instance_id, chain_generation, id`). Exactly one generation accepts writes at a time.
  - On startup, only the latest generation is verified. Content corruption there — a row whose
    own hash doesn't match its bytes, a row that doesn't chain to its predecessor, an
    unparseable column, or a valid tail at the id counter's limit — is classified by cause and
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

## Breaking Changes

- The `PostgreSQL` audit schema's primary key changed from `(instance_id, id)` to
  `(instance_id, chain_generation, id)`. This backend has no released migration path yet —
  drop and let the KMS recreate `kms_audit_events` rather than expecting an in-place upgrade.
