## Features

### Audit

- The KMS now **always starts**, regardless of the state of the audit log. Startup no longer
  aborts on a corrupted or tampered audit log tail; recovery is routed by cause instead:
  - A **torn (interrupted) write** — process killed mid-write — is truncated and the chain
    continues in place, with an `audit:torn-write-recovered` sentinel recording the bytes
    discarded.
  - A **tampered row or structural garbage** at the tail triggers **seal-and-roll**: the
    corrupted file is renamed aside as `<name>.<timestamp>.<hex>.corrupt.<ext>` forensic
    evidence, and a fresh chain starts with an `audit:reanchor` event recording the sealed
    file's name, size, and SHA-256.
- The KMS now verifies the **entire** hash chain on every boot — not just the last event —
  so a tampered row anywhere in the file is caught, not only at the tail. This runs
  unconditionally (there is no configuration to reduce it back to a tail-only check) and is
  streamed line-by-line, so it stays cheap in time and memory regardless of log size.
- A best-effort, cross-platform, non-blocking exclusive lock (`<audit-file>.lock`) now
  prevents two KMS instances from corrupting the same audit log during a rolling update on a
  shared volume. If the lock is held by a live peer, the KMS still starts immediately: events
  are buffered in the existing bounded channel and flushed in order once the lock is acquired,
  never blocking startup.
- A genuinely unwritable audit path (wrong permissions, read-only mount, disk I/O error) no
  longer aborts startup either. The KMS boots and serves traffic normally; the audit writer
  logs each dropped event and periodically retries opening the path, self-healing the moment
  the fault clears.
- `ckms audit verify --path` now accepts a **directory** in addition to a single file, verifying
  every `*.jsonl` file found as an independent hash chain. For every `audit:reanchor` event
  encountered, it also confirms the referenced sealed evidence file still exists on disk and its
  SHA-256 still matches the digest recorded in the event — exiting non-zero
  (`MISSING EVIDENCE` / `TAMPERED EVIDENCE`) if the sealed file was deleted or altered after the
  fact.

## Breaking Changes

- `AuditFileStore::resume_chain`'s previous behaviour of aborting server startup on a tampered
  or unparseable last audit event has been removed. Deployments that relied on the KMS refusing
  to start on audit-log corruption (as an operator acknowledgement gate) must now monitor the
  new `kms.audit.startup_recovery.total` metric and/or server logs (`AuditFileStore: sealed
  corrupted audit log as ...`) instead — there is no configuration option to restore the old
  abort-on-corruption behaviour.

---

Supersedes ADR-0003's fail-fast startup design; see the new ADR documenting the always-start /
route-by-cause recovery model.
