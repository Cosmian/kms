## Features

### Audit logging — tamper-evident JSONL event log

Cosmian KMS now writes a cryptographically-chained audit trail of every KMIP
operation to a local JSONL file.

**Chain design**

Each persisted row carries:

- `id` — monotonically increasing integer (i64, big-endian in the hash)
- `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
- `row_hash` — SHA-256 of this row's canonical bytes (including `prev_hash`)

Truncating, reordering, or modifying any field in any row breaks the chain and
is detected by `ckms audit verify`.

**Durability**

Each write is followed by `fsync` (`File::sync_data()`) so events survive an OS
crash or power failure. A `sync_data()` is also issued when the writer task
drains on graceful server shutdown, ensuring no in-flight events are lost.

**Startup resilience**

On restart the server reads only the last 64 KiB of the existing log (O(1)
regardless of file size) to resume the chain. If the last event's `row_hash`
does not verify, the server refuses to start and reports the corrupted line —
preventing silent chain continuation from a forged or truncated tail.

**Drop policy under saturation**

The writer task communicates via a bounded channel whose capacity is set by
`--audit-channel-capacity` / `KMS_AUDIT_CHANNEL_CAPACITY` (default: **4 096**).
When the channel is full, the enqueue call returns immediately and logs an
`error!` — the request path is never blocked. Dropped events are not recorded
in the chain; the compliance log is simply incomplete for that burst. See
[SECURITY.md](../SECURITY.md) for operational guidance.

### New CLI command: `ckms audit verify`

```
ckms audit verify --path <audit.jsonl> [--verbose]
```

Reads the audit file line by line, verifies each event's `row_hash`, and checks
every `prev_hash` link. Exits non-zero on the first tampered or broken link.
With `--verbose`, prints each event id, timestamp, operation, and `chain=ok`.

### CEF output format

`AuditEventFull` can be serialised as a
[Common Event Format (CEF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
line via `to_cef_line()`. This enables direct ingestion into SIEM systems such
as ArcSight, Splunk, or QRadar.

### Configuration

| CLI flag                   | Env var                      | Default      | Description                                                                               |
| -------------------------- | ---------------------------- | ------------ | ----------------------------------------------------------------------------------------- |
| `--audit-log-path`         | `KMS_AUDIT_LOG_PATH`         | _(disabled)_ | Path to the JSONL audit log file. Audit logging is disabled when unset.                   |
| `--audit-channel-capacity` | `KMS_AUDIT_CHANNEL_CAPACITY` | `4096`       | In-memory channel capacity. Raise if you see `"AuditFileStore: channel full"` in the log. |

### Security hardening (this session)

Implemented during code review of the initial `file_store.rs`:

- **Durability**: replaced `file.flush()` (no-op on `std::fs::File`) with
  `file.sync_data()` after every write and on graceful shutdown.
- **Fail-fast startup**: the audit file is opened in `AuditFileStore::start()`
  before spawning the writer task; an unwritable path aborts server startup
  immediately instead of silently disabling audit logging at runtime.
- **Tail-seek resume**: `resume_chain` seeks to the last 64 KiB instead of
  reading the entire file — O(1) startup for GB-scale logs.
- **Tamper detection at startup**: `verify_event()` is called on the last
  persisted event before trusting its `row_hash` as the chain seed.
- **Redundant `Arc` removed**: `AuditFileStore::sender` is now
  `mpsc::Sender<_>` directly (`Sender` is already `Arc`-backed).
- **Clippy hygiene**: `&PathBuf` → `&Path` in all signatures; `#[allow]`
  attributes carry inline justifications.
- **Test coverage**: replaced three `todo!()` stubs with real tests:
  `enqueue_drops_when_channel_full`, `chain_resumes_on_restart`,
  `write_failure_does_not_advance_chain`, plus
  `resume_rejects_tampered_last_line`.
