---
title: "ADR-0003: Tamper-Evident JSONL Audit Log — Single-Writer Architecture"
status: "Superseded"
date: "2026-07-09"
authors: "contributors, security architects, compliance engineers"
tags: ["architecture", "decision", "audit", "compliance", "security"]
supersedes: ""
superseded_by: "ADR-0006"
---

# ADR-0003: Tamper-Evident JSONL Audit Log — Single-Writer Architecture

## Status

**Superseded by [ADR-0006](2026-08-14-006-audit-log-always-start-recovery.md)** for the startup
fail-fast behavior described below ("a mismatch aborts startup with a clear error" /
"fail-fast: an unwritable path aborts server startup"). The KMS now always starts and routes
audit-log tail recovery by cause instead. The channel architecture, hash-chain design, and
overflow policy described in this document remain accurate and in effect.

Originally: Accepted

## Context

Cosmian KMS must produce a verifiable, tamper-evident record of every KMIP operation to satisfy:

- **FIPS key lifecycle accountability** — every Create, Rotate, Destroy event must be traceable
  to a principal.
- **PCI-DSS Req 10** — automated audit trail for all system components; individual access to
  cardholder data must be logged with user identity and timestamp.
- **HIPAA §164.312(b)** — hardware and software activity in electronic information systems.
- **NIST SP 800-66r2** — audit controls for ePHI systems.

The KMS serves concurrent KMIP requests across multiple Actix-web worker threads. A naive
"each thread appends directly to a file" design would require a mutex around every write, adding
latency on the hot request path and risking interleaved or corrupted JSONL lines.

## Decision

Implement the audit subsystem as a **single-writer background task** accessed via a bounded
`tokio::sync::mpsc` channel:

- The Actix-web middleware calls `enqueue()` — a non-blocking `try_send` — after each KMIP
  operation. The request thread never touches the file.
- One background `tokio::spawn` task is the sole owner of the open file, the monotonic id
  counter, and the rolling `prev_hash`. No mutex is needed.
- Each persisted JSONL row carries a SHA-256 hash chain:
    - `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
    - `row_hash` — SHA-256 of this row's canonical bytes (including `prev_hash`)
- Every write is followed by `sync_data()` (one `fsync` per event) to guarantee durability
  against OS crash or power failure.
- On server restart the writer reads only the last 64 KiB of the existing log (O(1) regardless
  of file size) to resume the chain. The last event's `row_hash` is verified before trusting it
  as the chain seed; a mismatch aborts startup with a clear error.
- The audit file is opened in `start()` **before** spawning the writer task (fail-fast: an
  unwritable path aborts server startup, not silently disables audit logging at runtime).

### Overflow policy

When the channel is full, incoming events are **dropped (drop-newest)** and an `ERROR` is
logged. The writer never blocks the request path. The hash chain advances normally; the
compliance log has a gap but stays structurally valid.

Ring-buffer semantics (drop-oldest) were explicitly rejected — see _Alternatives Considered_.

### Channel capacity

The channel capacity is operator-configurable via `--audit-channel-capacity` /
`KMS_AUDIT_CHANNEL_CAPACITY` (default: **4096**). The default absorbs ~4 seconds of sustained
load at 1 000 req/s given one `fsync` ≈ 1 ms on NVMe storage (4 096 × ~500 B ≈ 2 MiB peak).

## Consequences

### Positive

- **POS-001**: Zero mutex contention on the hot request path — `try_send` is lock-free.
- **POS-002**: Write ordering is guaranteed; no possibility of interleaved JSONL lines.
- **POS-003**: The hash chain provides cryptographic tamper detection: any deletion,
  reordering, or field modification in any row is detectable offline with
  `ckms audit verify --path <file>`.
- **POS-004**: Durability: `sync_data()` per write means at most one event is lost on a hard
  crash; the chain resumes cleanly from the last durably written row.
- **POS-005**: O(1) startup regardless of log file size — only the last 64 KiB is read.
- **POS-006**: Fail-fast startup detects unwritable paths immediately, before any requests
  are served.
- **POS-007**: Channel capacity is user-configurable, allowing operators to tune
  burst-buffering vs. memory footprint for their deployment.

### Negative

- **NEG-001**: One `fsync` per event caps write throughput to ~1 000–2 000 events/sec on
  typical NVMe storage. High-throughput deployments (>1 000 req/s) will see channel
  saturation and dropped events.
- **NEG-002**: Under saturation, dropped events are undetectable in the chain — a compliance
  auditor cannot distinguish "nothing happened" from "events were silently lost" without
  monitoring the server log for `"AuditFileStore: channel full"`.
- **NEG-003**: `object_uid` and `algorithm` fields are always `None` — the HTTP middleware
  layer does not have access to the deserialized KMIP payload. Filling these requires injecting
  KMIP-layer extensions into the request context (tracked in `tradeoofs.md` T1).
- **NEG-004** ✅ **Resolved**: Batch KMIP requests now produce one audit event **per `BatchItem`**,
  linked by a shared `request_id` (UUID v4). Each item carries its own `operation`,
  `object_uid`, `algorithm`, and per-item `result` parsed from the `ResponseMessage`
  `ResultStatus`/`ResultReason`. See `tradeoofs.md` T2.

## Alternatives Considered

### Ring-buffer overflow (drop-oldest)

- **ALT-001 Description**: Replace the bounded MPSC with a lock-protected `VecDeque` or a
  lock-free ring. When full, evict the oldest buffered (not-yet-written) event to make room
  for the newest.
- **ALT-002 Rejection Reason**: Vulnerable to **log-flooding attacks** — an adversary
  generating a burst of noise events can overwrite early incriminating events still in the
  buffer before they reach disk. Drop-newest is the standard policy for compliance-grade audit
  logs (`auditd`, `rsyslog`, `syslog-ng` all use it). Additionally, for KMS events that form
  causal chains (Create → Encrypt → Destroy), losing the beginning of a burst (Create) while
  keeping the end (Destroy) is worse forensically than the reverse.

### Mutex-protected direct file append

- **ALT-003 Description**: Each Actix-web worker acquires a `Mutex<File>` and appends
  directly, computing the hash in the locked section.
- **ALT-004 Rejection Reason**: Contention across worker threads adds latency on every KMIP
  request. Serialisation is only guaranteed if all writers hold the same lock, which rules out
  async tasks on different threads. Deadlock risk if a writer panics while holding the lock.

### Blocking write with back-pressure

- **ALT-005 Description**: Replace `try_send` with `send` (async await) so the request thread
  blocks until the writer has capacity.
- **ALT-006 Rejection Reason**: Propagates file-I/O latency (including `fsync`) directly into
  request latency. Under storage degradation, all KMIP requests stall. Unacceptable for a
  production KMS. The bounded channel isolates storage hiccups from the request path.

### Batched fsync (every N events or every T ms)

- **ALT-007 Description**: Accumulate N events in the writer before calling `sync_data()`,
  trading durability for throughput.
- **ALT-008 Rejection Reason**: Increases the window of events lost on a crash (up to N, not
  1). For a compliance audit trail this is a clear regression. Deferred as a Phase 2 option
  for high-throughput deployments that document the tradeoff explicitly.

## Implementation Notes

- **IMP-001**: Core implementation: `crate/server/src/core/audit/file_store.rs`
- **IMP-002**: Config structs: `crate/server/src/config/command_line/audit_config.rs`;
  resolved params: `crate/server/src/config/params/server_params.rs`
- **IMP-003**: Wiring point: `crate/server/src/core/kms/mod.rs` →
  `create_audit_store(&server_params)` → `AuditFileStore::start(path, channel_capacity)`
- **IMP-004**: Middleware enqueue: `crate/server/src/middlewares/audit.rs`
- **IMP-005**: Offline verification CLI: `crate/clients/clap/src/actions/audit.rs`
  (`ckms audit verify --path <file>`)
- **IMP-006**: Saturation monitoring — alert on `"AuditFileStore: channel full"` in server
  log. See `SECURITY.md` §7 for operational guidance.
- **IMP-007**: Known gaps tracked in `.agents/tradeoofs.md`: T1 (`object_uid` always None),
  T2 (batch event granularity), T3 (silent drop detectability), T6 (log rotation breaks
  offline verify), T7 (XFF spoofing).

## References

- **REF-001**: `ADR-0002` — Key Auto-Rotation Keyset Chain Design (hash chain precedent)
- **REF-002**: PCI-DSS v4.0 Requirement 10 — Track and Monitor All Access
- **REF-003**: NIST SP 800-92 — Guide to Computer Security Log Management
- **REF-004**: FIPS 140-3 — key lifecycle accountability requirements
- **REF-005**: `SECURITY.md` §7 — Audit log saturation operational guidance
- **REF-006**: `.agents/tradeoofs.md` — full list of known gaps and planned fixes
- **REF-007**: `CHANGELOG/feat_audit_and_siem.md` — branch-level change log for this feature
