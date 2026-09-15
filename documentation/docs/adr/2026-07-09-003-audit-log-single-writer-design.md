---
title: "ADR-0003: Tamper-Evident JSONL Audit Log — Single-Writer Architecture"
status: "Accepted"
date: "2026-07-09"
authors: "contributors, security architects, compliance engineers"
tags: ["architecture", "decision", "audit", "compliance", "security"]
supersedes: ""
superseded_by: ""
---

# ADR-0003: Tamper-Evident JSONL Audit Log — Single-Writer Architecture

## Status

Accepted.
Startup verification and recovery are specified by
[ADR-0006](2026-08-14-006-audit-log-always-start-recovery.md).

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
- On server restart the writer streams the existing chain to verify every row, then uses a
  64 KiB tail window to classify the final rows for recovery.
- File opening, locking, verification, and recovery run inside the background writer task.
  Audit-file faults do not block KMS startup; recovery behavior is defined by ADR-0006.

### Overflow policy

When the channel is full, incoming events are **dropped (drop-newest)** and an `ERROR` is
logged. The writer never blocks the request path. Before its next regular event, the writer
adds an `audit:eviction` sentinel to the hash chain with the number of dropped events.

Ring-buffer semantics (drop-oldest) were explicitly rejected — see _Alternatives Considered_.

### Channel capacity

The channel capacity is operator-configurable via `--audit-channel-capacity` /
`KMS_AUDIT_CHANNEL_CAPACITY` (default: **4096**). The default absorbs ~4 seconds of sustained
load at 1 000 req/s given one `fsync` ≈ 1 ms on NVMe storage (4 096 × ~500 B ≈ 2 MiB peak).

## Consequences

### Positive

- **POS-001**: No file mutex or blocking file I/O on the hot request path; `try_send` is
  non-blocking.
- **POS-002**: Write ordering is guaranteed; no possibility of interleaved JSONL lines.
- **POS-003**: The hash chain provides cryptographic tamper detection: field modification,
  reordering, or deletion that breaks a chain link is detectable offline with
  `ckms audit verify --path <file>`.
- **POS-004**: Each completed row is synchronized before the writer processes the next queued
  event. Events still waiting in the in-memory channel remain volatile.
- **POS-005**: Startup verification uses constant memory: the chain is streamed line by line,
  and tail classification reads at most 64 KiB.
- **POS-006**: Audit-file I/O faults are retried by the background writer without preventing
  the KMS from serving requests.
- **POS-007**: Channel capacity is user-configurable, allowing operators to tune
  burst-buffering vs. memory footprint for their deployment.

### Negative

- **NEG-001**: One `fsync` per event caps write throughput to ~1 000–2 000 events/sec on
  typical NVMe storage. High-throughput deployments (>1 000 req/s) will see channel
  saturation and dropped events.
- **NEG-002**: The eviction sentinel makes saturation visible but cannot reconstruct the
  contents of dropped events.
- **NEG-003**: Audit context extraction is best-effort. Operations whose TTLV layout does not
  expose an object UID or algorithm may persist those fields as `None`.
- **NEG-004** ✅ **Resolved**: Batch KMIP requests now produce one audit event **per `BatchItem`**,
  linked by a shared `request_id` (UUID v4). Each item carries its own `operation`,
  `object_uid`, `algorithm`, and per-item `result` parsed from the `ResponseMessage`
  `ResultStatus`/`ResultReason`.

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
  `create_audit_store(&server_params)` →
  `AuditFileStore::start_with_max_size(path, channel_capacity, max_size_bytes)`
- **IMP-004**: Middleware enqueue: `crate/server/src/middlewares/audit.rs`
- **IMP-005**: Offline verification CLI: `crate/clients/clap/src/actions/audit.rs`
  (`ckms audit verify --path <file>`)
- **IMP-006**: Saturation monitoring — alert on `"AuditFileStore: channel full"` in server
  logs. See `SECURITY.md`, "Security Best Practices," item 7.

## References

- **REF-001**: `ADR-0002` — Key Auto-Rotation Keyset Chain Design (hash chain precedent)
- **REF-002**: PCI-DSS v4.0 Requirement 10 — Track and Monitor All Access
- **REF-003**: NIST SP 800-92 — Guide to Computer Security Log Management
- **REF-004**: FIPS 140-3 — key lifecycle accountability requirements
- **REF-005**: `SECURITY.md`, "Security Best Practices," item 7 — Audit log saturation
  operational guidance
