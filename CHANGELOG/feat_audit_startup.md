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
  streamed line-by-line, so memory use stays constant regardless of log size (runtime is still
  linear in the number of rows).
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
- New optional `--audit-file-max-size-bytes` / `KMS_AUDIT_FILE_MAX_SIZE_BYTES` /
  `[audit.file] max_size_bytes` caps the audit file at a configured byte size. Omitted (the
  default) means unlimited — today's behavior is unchanged. This is a **write-stop cap, not
  rotation or retention**: the writer never deletes, truncates, or rolls the file. The event
  that pushes the file to or past the cap is still persisted; every event after it is dropped
  (subject to `--audit-failure-mode`, exactly like a full channel or a dead writer) until the
  log is remediated and the KMS is restarted. A `0` value is rejected as invalid configuration.

## Breaking Changes

- `AuditFileStore::resume_chain`'s previous behaviour of aborting server startup on a tampered
  or unparseable last audit event has been removed. Deployments that relied on the KMS refusing
  to start on audit-log corruption (as an operator acknowledgement gate) must now monitor server
  logs instead — look for `AuditFileStore: sealed corrupted audit log as ...` or
  `AuditFileStore: torn write recovered` errors. There is no configuration option to restore the
  old abort-on-corruption behaviour.

---

Supersedes ADR-0003's fail-fast startup design; see the new ADR documenting the always-start /
route-by-cause recovery model.
