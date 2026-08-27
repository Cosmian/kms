---
title: "ADR-0006: Audit Log Always-Start Recovery — Route by Cause, Not One Global Policy"
status: "Accepted"
date: "2026-08-14"
authors: "contributors, security architects, compliance engineers"
tags: ["architecture", "decision", "audit", "compliance", "security", "availability"]
supersedes: "ADR-0003"
superseded_by: ""
---

# ADR-0006: Audit Log Always-Start Recovery — Route by Cause, Not One Global Policy

## Status

Accepted. Supersedes the startup-abort behavior of ADR-0003 (§ "Fail-fast startup" /
`resume_chain`); ADR-0003's single-writer channel architecture, hash-chain design, and channel
overflow policy remain unchanged and in effect.

## Context

ADR-0003 established that `AuditFileStore::start()` aborts server startup if the last event in
an existing audit log fails to parse or fails `verify_event` — treating this as tamper/crash
evidence that must be triaged by an operator before the KMS serves traffic again.

In practice this makes the audit subsystem a single point of failure for the entire KMS: any
condition at the tail of the log — a process killed mid-write (OOM, pod eviction, power loss), a
disk fault that truncated the last line, or genuine tampering — takes down the whole key
management service, not just audit logging. At fleet scale, ungraceful restarts (the common
case for "torn write") are frequent; a KMS that cannot restart until an operator manually repairs
or deletes the last line of a log file is not acceptable availability posture for a system whose
entire purpose is to keep cryptographic operations available.

The two failure conditions at the tail are also structurally different and were being handled
identically:

- **Torn tail write**: the last complete, *verified* row is fully intact and trustworthy; only
  an incomplete trailing fragment needs to be discarded.
- **Tampered or garbage row**: a complete line whose hash doesn't match, or unparseable bytes
  that aren't an interrupted write. Continuity across this point cannot be trusted.

Applying "always keep writing in place" to the second case would corrupt the chain permanently
with no repair path. Applying "always start a fresh file" to the first case fragments the log on
every ungraceful restart.

## Decision

**The KMS always starts.** No condition found in the audit log at boot may abort startup. Audit
recovery routes by cause instead of one global policy.

### Discriminator: the file's final byte

- Ends in `\n` → the write completed.
  - Last row parses + verifies → **resume** normally.
  - Last row doesn't parse or its hash doesn't match → **seal-and-roll** (structural garbage /
    tampered row).
- Does not end in `\n` → the write was interrupted.
  - The row is nonetheless complete and verified (crash landed between the JSON write and the
    trailing-newline write) → **resume**, repairing the missing line terminator before the next
    append.
  - The row is incomplete/invalid, but the row before it (or genesis) verifies → **truncate the
    torn fragment and continue** in place.
  - The row before it is also untrustworthy → **seal-and-roll**.

The tail-window scan retains the **last two** candidate rows, not one, so truncate-and-continue
can fall back past a torn fragment to the prior verified row.

### Path 1 — Truncate-and-continue

`File::set_len` to the byte offset immediately after the last row that both parsed and verified,
then appends an `audit:torn-write-recovered` sentinel recording the bytes discarded and the
offset. **Invariant, enforced and tested**: a verified row is never removed under any
circumstance.

### Path 2 — Seal-and-roll

1. Stream-hash the full existing file (SHA-256, no full load).
2. `fs::rename` the old file aside as `<stem>.<RFC3339-compact-UTC>.<8-hex>.corrupt.<ext>` —
   forensic evidence, never modified or deleted by this code path.
3. Open a fresh file at the original, unchanged configured path.
4. Write an `audit:reanchor` event as row 0 of the new chain (`id=0`, `prev_hash=[0;32]`) —
   a new chain root, **not** a continuation. The sealed file's tail is by definition untrusted,
   so asserting continuity across it would manufacture false provenance. The event's new
   `details` field (see below) records the sealed file's name, SHA-256, size, the claimed last
   id, the failure offset, and the reason (`hash_mismatch` | `unparseable`).
5. `fsync` the containing directory so the rename is itself durable.

Order is load-bearing: rename before open, so the lock holder never observes a half-migrated
state.

### Concurrency: a lock is a prerequisite, not an enhancement

A best-effort, non-blocking, cross-platform exclusive lock (`flock`-equivalent via the `fs4`
crate) on a `<path>.lock` sidecar prevents two live KMS instances from both mutating the same
audit file when the underlying filesystem honors `flock` semantics for the lock holder that
matters most in practice — a rolling update where the new pod becomes Ready before the old pod
terminates. This is **not** a guarantee for arbitrary shared/network volumes: `flock` reliability
over NFS-backed `ReadWriteMany` mounts depends on the storage backend's lock-manager support, so
multiple KMS instances must still never be configured to write to the same audit file as a
steady-state multi-writer setup — see
[High availability: file-based audit logging is not multi-instance safe](../installation/high_availability_mode.md#deployment-options).

- Lock acquired → sole writer → free to classify, truncate/seal, and write.
- Lock held by a peer → **the KMS still starts and serves immediately**. The writer does not
  mutate the file. Events are buffered in the existing bounded channel and flushed in order once
  the lock is acquired; only a channel that fills to capacity during the wait spills to
  drop + eviction-sentinel, exactly like saturation during normal operation. Lock acquisition
  never blocks startup and is retried in the background.

### Self-healing on content-independent I/O faults

A path that cannot be opened for a reason unrelated to log content (`EACCES`, `EIO`, a read-only
mount) is a deployment fault, not evidence of tampering. The KMS boots and serves traffic; the
writer logs an error per dropped event and periodically retries opening the path, so audit
logging resumes automatically the moment the fault is corrected — no restart required.

### Startup verification is unconditional, failure handling is not configurable

Every boot verifies every row's hash and its link to the previous row, from the first event to
the second-to-last — not just the tail window — catching a corruption anywhere in the file, not
only at the end. This was initially shipped as an opt-in `startup_verify = "full"` toggle
(`tail` O(1) by default, `full` O(log size) opt-in); the toggle was removed because the
assumption behind it — that whole-chain verification is too expensive to run by default — did
not hold up: hashing and JSON-decoding a JSONL row is cheap per row, and skipping most of the
log by default left the common case blind to interior tampering for no real benefit. Verification
now always runs, streamed line-by-line rather than loaded into memory, so memory use stays
constant regardless of log size — runtime is still linear in the number of rows, but that cost is
small enough per row (a hash and a JSON decode) to be an acceptable default. As with the rest of
this ADR, there is **no** corresponding "abort on corruption" toggle: unlike ADR-0003's design,
this is not configurable, period.

### Offline verification (`ckms audit verify`) gains directory + evidence-integrity support

- `--path` accepts a directory, verifying every non-sealed `*.jsonl` file as an independent
  chain. Sealed `*.corrupt.jsonl` evidence is digest-checked through its live log's reanchor,
  not required to form a valid chain itself.
- For every `audit:reanchor` event, confirms the referenced sealed file exists on disk and its
  SHA-256 matches the digest recorded in the event — exits non-zero on a mismatch or missing
  file. This is what makes deleting or altering sealed evidence after the fact detectable.
- Torn-write sentinels are informational; reanchor records are warning-level.

## Consequences

### Positive

- **POS-001**: The KMS's core cryptographic service availability is no longer coupled to the
  audit log's integrity. A corrupted or tampered audit tail degrades observability, never
  availability.
- **POS-002**: Torn writes — the common case for ungraceful restarts at fleet scale — no longer
  fragment the log; the chain continues in place with a visible sentinel.
- **POS-003**: Tampering is still fully detectable and evidence-preserving: the corrupted file is
  never deleted, only renamed aside, and its integrity is independently checkable via SHA-256
  recorded in the reanchor event and cross-verified by `ckms audit verify`.
- **POS-004**: The lock removes the specific, previously undefended failure mode of a rolling
  update silently splitting the log across two writers with no marker in either file.
- **POS-005**: Verification always covers the whole chain, not just the tail — an interior
  tamper is caught on every boot, with no opt-in flag an operator could forget to set.

### Negative

- **NEG-001**: Removing the fail-fast abort means an operator who previously relied on "the KMS
  won't start until I look at this" as a forcing function for triage must now rely on the new
  recovery audit events and server logs instead. This is an explicit, accepted trade: a
  compliance log gap must never become a cryptographic service outage.
- **NEG-002**: Sealed `*.corrupt.jsonl` files accumulate on disk with no built-in rotation or
  retention — deferred to the separate log-rotation work item.
- **NEG-003**: The lock is host/kernel-scoped (`flock`-equivalent), not a distributed coordination
  mechanism. It correctly resolves the transient rolling-update overlap (old pod exits, new pod
  acquires), but it is **not a multi-writer backend**: if multiple long-lived KMS instances point
  at the same shared audit file (e.g. a `ReadWriteMany` volume across Kubernetes replicas), only
  the instance holding the lock ever writes — the others retry indefinitely and their events are
  never recorded, silently. Sustained horizontal scaling must use one audit file per instance
  (the default), not a shared one. A genuinely multi-writer-safe, centrally consolidated audit
  trail requires a transactional backend (PostgreSQL audit backend, in progress) where a unique
  constraint, not a file lock, arbitrates concurrent writers.

## Alternatives Considered

### Keep fail-fast, add an operator override flag only

- **ALT-001 Description**: Keep ADR-0003's abort-on-corruption behavior as the default, and add
  an opt-in `--audit-recover-on-corruption` flag for operators who want always-start.
- **ALT-002 Rejection Reason**: Explicitly rejected. The mandate is that the KMS must always be
  startable; making that conditional on a flag means the default deployment still has a
  single point of failure. There is intentionally no configuration path back to the old
  behavior.

### Ring-buffer-style "keep the newest bytes" truncation without a discriminator

- **ALT-003 Description**: On any tail anomaly, unconditionally truncate the last line and
  continue, regardless of whether it was a torn write or a tampered/garbage row.
- **ALT-004 Rejection Reason**: Would silently destroy evidence of tampering — a hash mismatch on
  a *complete* row is meaningfully different from an incomplete one, and only the former
  warrants preserving the whole file as forensic evidence via seal-and-roll.

### fcntl (POSIX) byte-range locks instead of flock-based advisory locks

- **ALT-005 Description**: Use `fcntl(F_SETLK)` for the cross-platform lock.
- **ALT-006 Rejection Reason**: POSIX `fcntl` locks are keyed by `(process, inode)`, not by open
  file descriptor — two different file descriptors in the *same* process can both "hold" the
  lock simultaneously, which does not model the actual hazard (two separate KMS *processes*).
  `flock`-based locks (via the `fs4` crate, which uses `flock(2)` on Unix and `LockFileEx` on
  Windows) are keyed by open file description and correctly conflict across processes and, for
  testing purposes, across independent file handles within one process.

## Implementation Notes

- **IMP-001**: Core implementation: `crate/server/src/core/audit/file_store.rs`
  (`classify_tail`, `TailOutcome`, `truncate_and_continue`, `seal_and_roll`, `writer_supervisor`,
  `try_acquire_lock`, `verify_interior_chain`).
- **IMP-003**: New `AuditEvent.details: Option<String>` field:
  `crate/access/src/audit/event.rs`; canonical-hash encoding (backward-compatible trailing
  optional segment, following the `request_id` precedent):
  `crate/access/src/audit/hash.rs`.
- **IMP-005**: Offline verification: `crate/clients/clap/src/actions/audit.rs`
  (`ckms audit verify --path <file|directory>`).
- **IMP-006**: Lock dependency: `fs4` (crate/server/Cargo.toml).

## References

- **REF-001**: `ADR-0003` — Tamper-Evident JSONL Audit Log — Single-Writer Architecture (the
  design this ADR amends; its channel/hash-chain/overflow-policy sections remain in effect)
- **REF-002**: PCI-DSS v4.0 Requirement 10 — Track and Monitor All Access
- **REF-003**: NIST SP 800-92 — Guide to Computer Security Log Management
- **REF-004**: `CHANGELOG/feat_audit_startup.md` — branch-level change log for this feature
