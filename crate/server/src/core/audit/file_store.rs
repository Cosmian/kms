//! Tamper-evident JSONL file backend for audit events.
//!
//! Architecture
//! ============
//! * `AuditFileStore` is a cheaply cloneable handle (wraps a channel `Sender`).
//! * A single background tokio task (`writer_supervisor`) is the **sole owner** of the
//!   audit file, the monotonic event counter, and the previous-row hash.  This
//!   design avoids any mutex around the file and guarantees write order under
//!   concurrent requests.
//! * The KMS always starts: `start()` returns synchronously and never blocks on file I/O
//!   or lock contention. Recovery, exclusive-lock acquisition, and opening the file all
//!   happen inside the writer task, retrying in the background on failure. Events
//!   enqueued in the meantime are genuinely queued (not dropped) up to the channel's
//!   bounded capacity — see `writer_supervisor`.
//! * The middleware calls `enqueue()` which is a non-blocking `try_send`.  If the
//!   channel is full (beyond the configured capacity) the draft is silently dropped
//!   and an error is logged — we never block the request path.
//!
//! Hash chain
//! ==========
//! Each persisted row carries:
//!   `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
//!   `row_hash`  — SHA-256 of this row's canonical bytes (including `prev_hash`)
//!
//! Use `ckms audit verify --path <file>` to validate the chain offline.

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cosmian_kms_access::audit::{
    AuditEvent, AuditEventDraft, AuditResult, compute_row_hash, verify_chain_link, verify_event,
};
use cosmian_logger::{debug, error};
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};

use crate::{error::KmsError, result::KResult};

/// Bytes read from the end of an existing log to locate the last complete event
/// at startup.  64 KiB comfortably covers many events; a single serialised
/// `AuditEventFull` is typically <2 KiB.
const TAIL_WINDOW: u64 = 65_536;

/// Message sent to the writer task over the channel.
enum WriterMsg {
    /// A draft event to persist. Boxed so the `Flush` variant (a bare `oneshot::Sender`)
    /// doesn't force every enum instance to reserve `AuditEventDraft`'s full size.
    Event(Box<AuditEventDraft>),
    /// A synchronization barrier: the writer acknowledges once every message
    /// enqueued before this one has been written (and, for `File`, `fsync`'d).
    /// Used by tests to await the writer's progress deterministically instead
    /// of sleeping. Only the test-only `flush()` constructs it, but the field
    /// type and writer-loop handler compile unconditionally.
    #[cfg_attr(not(test), allow(dead_code))]
    Flush(oneshot::Sender<()>),
}

/// A cheaply cloneable handle to the audit writer task.
///
/// Cloning this value is O(1) — `tokio::sync::mpsc::Sender` is already backed
/// by an internal `Arc`, and `dropped_count` is an `Arc<AtomicU64>`.
/// All clones share the same underlying channel and writer task.
#[derive(Clone)]
pub(crate) struct AuditFileStore {
    sender: mpsc::Sender<WriterMsg>,
    /// Counts events dropped because the channel was full.
    /// Checked by the writer loop to emit a sentinel event before the next real event.
    dropped_count: Arc<AtomicU64>,
}

impl AuditFileStore {
    /// Initialises the audit file store and spawns the background writer task.
    ///
    /// Returns immediately: the channel is created and handed back synchronously so the
    /// middleware can start enqueueing events right away, even before the writer has
    /// acquired the lock or opened the file. `channel_capacity` is the number of events
    /// that can be buffered before new events are dropped. Must be ≥ 1.
    ///
    /// Recovery, locking, and opening all happen inside the spawned writer task — see
    /// `writer_supervisor`. This call never blocks on file I/O or lock contention.
    ///
    /// # Errors
    /// Returns an error only if `channel_capacity` is 0 — a pure configuration mistake,
    /// not a runtime condition. Every other fault (I/O, lock contention, log corruption)
    /// is handled inside the writer task without aborting startup; see `writer_supervisor`.
    pub(crate) fn start(
        path: &Path,
        channel_capacity: usize,
    ) -> KResult<Self> {
        if channel_capacity == 0 {
            return Err(KmsError::ServerError(
                "audit: channel_capacity must be at least 1".to_owned(),
            ));
        }

        let (tx, rx) = mpsc::channel::<WriterMsg>(channel_capacity);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let dropped_count_for_writer = Arc::clone(&dropped_count);
        let path = path.to_path_buf();

        tokio::spawn(async move {
            writer_supervisor(path, rx, dropped_count_for_writer).await;
        });

        Ok(Self {
            sender: tx,
            dropped_count,
        })
    }

    /// Enqueues one or more draft events for writing.  Non-blocking: if the channel is
    /// full an event is dropped and the `dropped_count` counter is incremented.  The writer
    /// loop drains that counter before each real event and emits a synthetic
    /// `operation = "audit:eviction"` sentinel that joins the hash chain — making drops
    /// detectable by `ckms audit verify` and compliance tools.
    ///
    /// **Note**: for batch requests, `try_send` is called per-draft sequentially.
    /// If the channel fills mid-batch, early drafts are persisted and later ones are
    /// dropped — the sentinel will account for them on the next successful enqueue.
    /// Returns `true` if every draft was successfully queued, `false` if any was dropped.
    pub(crate) fn enqueue(&self, drafts: impl IntoIterator<Item = AuditEventDraft>) -> bool {
        let mut all_queued = true;
        for draft in drafts {
            match self.sender.try_send(WriterMsg::Event(Box::new(draft))) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    error!("AuditFileStore: channel full, dropping audit event");
                    all_queued = false;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    error!("AuditFileStore: writer task has stopped, audit event dropped");
                    all_queued = false;
                }
            }
        }
        all_queued
    }

    /// Awaits until every event enqueued before this call has been written by
    /// the writer task (and, for the real `File` sink, `fsync`'d). Unlike
    /// `enqueue`, this uses a blocking `send` so the barrier itself is never
    /// dropped under channel saturation.
    ///
    /// Intended for tests and offline tooling that need a deterministic
    /// drain point instead of a fixed sleep. A no-op if the writer task has
    /// already stopped.
    // Only called from test code today; kept as a real (non-cfg-gated) crate API
    // so `WriterMsg::Flush` stays a normal, always-constructed variant instead of
    // needing parallel cfg(test)/cfg(not(test)) match arms in the hot writer loop.
    #[allow(dead_code, reason = "test-only today; a genuine crate API, not dead")]
    pub(crate) async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(WriterMsg::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

/// Why a row triggered seal-and-roll instead of resuming or truncating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealReason {
    /// A complete, well-formed row whose `row_hash` doesn't match its own bytes.
    HashMismatch,
    /// Bytes that don't deserialize as an `AuditEvent` at all.
    Unparseable,
}

impl SealReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash_mismatch",
            Self::Unparseable => "unparseable",
        }
    }
}

/// Result of parsing+verifying one candidate JSONL row.
enum RowCheck {
    /// Parsed and `row_hash` matches.
    Verified(AuditEvent),
    /// Parsed but `row_hash` doesn't match its own bytes — tampered.
    HashMismatch(AuditEvent),
    /// Didn't deserialize as an `AuditEvent` at all.
    Unparseable,
}

fn check_row(line: &str) -> RowCheck {
    match serde_json::from_str::<AuditEvent>(line) {
        Ok(event) if verify_event(&event) => RowCheck::Verified(event),
        Ok(event) => RowCheck::HashMismatch(event),
        Err(_) => RowCheck::Unparseable,
    }
}

/// Outcome of classifying the tail of an existing (or absent) audit log at startup.
/// Routes recovery by cause instead of one global policy — see the module docs.
#[derive(Debug)]
enum TailOutcome {
    /// No file, or an empty one: start a brand-new chain.
    Genesis,
    /// The tail is trustworthy; continue the chain from it.
    Resume {
        next_id: i64,
        prev_hash: [u8; 32],
        /// The file's last byte isn't `\n` even though the last row is valid — the
        /// trailing newline write didn't make it to disk. Must be repaired before the
        /// next append or the next row would concatenate onto this one.
        needs_leading_nl: bool,
    },
    /// A torn (interrupted) write: the last row is incomplete, but the row before it
    /// (or genesis) is trustworthy. Truncate the torn fragment and continue in place.
    TruncateContinue {
        /// Byte length to truncate the file to — always the end of the last verified row.
        keep_len: u64,
        next_id: i64,
        prev_hash: [u8; 32],
        bytes_discarded: u64,
        discard_offset: u64,
    },
    /// A complete row is tampered, or the tail is structural garbage with no trustworthy
    /// anchor to fall back to. Seal the file aside as evidence and start a fresh chain.
    SealAndRoll {
        reason: SealReason,
        claimed_last_id: Option<i64>,
        failure_offset: u64,
    },
}

/// Result of verifying every audit row except the physical tail row.
///
/// `previous_event` is the row the tail must link to when the tail is complete.
enum InteriorChainOutcome {
    /// Every interior row is valid and linked; the physical tail remains for `classify_tail`.
    Valid {
        previous_event: Option<AuditEvent>,
    },
    /// An interior row failed verification or chain-link validation.
    Broken {
        reason: SealReason,
        claimed_last_id: Option<i64>,
        failure_offset: u64,
    },
}

/// Classifies the tail of `path` to decide how startup should recover.
///
/// Reads only the last `TAIL_WINDOW` bytes (O(1) regardless of log size) and retains the
/// last **two** candidate rows so `TruncateContinue` can fall back past a torn fragment to
/// the row before it.
///
/// # Errors
/// Returns an error only for I/O faults (cannot open/stat/read the path) — never for a
/// data-corruption condition, which is always routed to a `TailOutcome` variant instead.
fn classify_tail(path: &Path, previous_event: Option<&AuditEvent>) -> KResult<TailOutcome> {
    if !path.exists() {
        return Ok(TailOutcome::Genesis);
    }

    let mut file = std::fs::File::open(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot open existing log file {}: {e}",
            path.display()
        ))
    })?;

    let file_len = file
        .metadata()
        .map_err(|e| KmsError::ServerError(format!("audit: cannot stat log file: {e}")))?
        .len();

    if file_len == 0 {
        return Ok(TailOutcome::Genesis);
    }

    // Seek to the tail window so startup cost is O(1) regardless of log size.
    let seek_pos = file_len.saturating_sub(TAIL_WINDOW);
    if seek_pos > 0 {
        file.seek(std::io::SeekFrom::Start(seek_pos))
            .map_err(|e| KmsError::ServerError(format!("audit: cannot seek log file: {e}")))?;
    }

    let mut buf = vec![0_u8; usize::try_from(file_len - seek_pos).unwrap_or(usize::MAX)];
    file.read_exact(&mut buf)
        .map_err(|e| KmsError::ServerError(format!("audit: cannot read log file tail: {e}")))?;

    let ends_with_newline = buf.last() == Some(&b'\n');
    let newline_positions: Vec<usize> = buf
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| (b == b'\n').then_some(i))
        .collect();

    if newline_positions.is_empty() {
        // No row boundary anywhere in the window: either one row far larger than
        // TAIL_WINDOW, or the seek landed inside one. Can't safely discriminate
        // torn-vs-tampered without risking misclassification — seal.
        return Ok(TailOutcome::SealAndRoll {
            reason: SealReason::Unparseable,
            claimed_last_id: None,
            failure_offset: seek_pos,
        });
    }

    // Complete rows are the byte ranges between consecutive newlines, [start, end).
    let mut rows: Vec<(usize, usize)> = Vec::new();
    let mut prev_end = 0_usize;
    for &nl in &newline_positions {
        rows.push((prev_end, nl));
        prev_end = nl + 1;
    }

    // If seek_pos > 0 the first row may be a fragment cut by the seek — it belongs to an
    // earlier, already-durable row and isn't needed for classification.
    if seek_pos > 0 {
        if rows.len() > 1 {
            rows.remove(0);
        } else {
            return Ok(TailOutcome::SealAndRoll {
                reason: SealReason::Unparseable,
                claimed_last_id: None,
                failure_offset: seek_pos,
            });
        }
    }

    // The trailing fragment after the final newline, if the buffer doesn't end in '\n'.
    let trailing = (!ends_with_newline).then_some((prev_end, buf.len()));

    let mut candidates: Vec<(String, u64, u64)> = rows
        .iter()
        .map(|&(s, e)| {
            (
                String::from_utf8_lossy(buf.get(s..e).unwrap_or(&[])).into_owned(),
                seek_pos + u64::try_from(s).unwrap_or(u64::MAX),
                seek_pos + u64::try_from(e).unwrap_or(u64::MAX),
            )
        })
        .collect();
    if let Some((s, e)) = trailing {
        candidates.push((
            String::from_utf8_lossy(buf.get(s..e).unwrap_or(&[])).into_owned(),
            seek_pos + u64::try_from(s).unwrap_or(u64::MAX),
            seek_pos + u64::try_from(e).unwrap_or(u64::MAX),
        ));
    }

    // Keep only the last two candidates.
    let keep_from = candidates.len().saturating_sub(2);
    let candidates = candidates.get(keep_from..).unwrap_or(&[]);
    let Some((last_line, last_start, last_end)) = candidates.last().cloned() else {
        // Can't happen (newline_positions was non-empty), but never panic on a
        // recovery path — fall back to the safest outcome.
        return Ok(TailOutcome::SealAndRoll {
            reason: SealReason::Unparseable,
            claimed_last_id: None,
            failure_offset: seek_pos,
        });
    };
    let second_last = (candidates.len() == 2)
        .then(|| candidates.first())
        .flatten()
        .map(|(line, _, _)| line);

    if ends_with_newline {
        return Ok(match check_row(&last_line) {
            RowCheck::Verified(event) if verify_chain_link(&event, previous_event) => {
                TailOutcome::Resume {
                    next_id: event.id + 1,
                    prev_hash: event.row_hash,
                    needs_leading_nl: false,
                }
            }
            RowCheck::Verified(event) => TailOutcome::SealAndRoll {
                reason: SealReason::HashMismatch,
                claimed_last_id: Some(event.id),
                failure_offset: last_start,
            },
            RowCheck::HashMismatch(event) => TailOutcome::SealAndRoll {
                reason: SealReason::HashMismatch,
                claimed_last_id: Some(event.id),
                failure_offset: last_start,
            },
            RowCheck::Unparseable => TailOutcome::SealAndRoll {
                reason: SealReason::Unparseable,
                claimed_last_id: None,
                failure_offset: last_start,
            },
        });
    }

    // No trailing newline. If the last row is itself complete and verified, it's simply
    // missing its terminator (crash between the JSON write and the newline write) — not a
    // torn write at all.
    if let RowCheck::Verified(event) = check_row(&last_line) {
        return Ok(if verify_chain_link(&event, previous_event) {
            TailOutcome::Resume {
                next_id: event.id + 1,
                prev_hash: event.row_hash,
                needs_leading_nl: true,
            }
        } else {
            TailOutcome::SealAndRoll {
                reason: SealReason::HashMismatch,
                claimed_last_id: Some(event.id),
                failure_offset: last_start,
            }
        });
    }

    // Otherwise this is a torn-write candidate: valid only if the row before it is a
    // trustworthy fallback anchor. `second_last` is always `Some` here: reaching this
    // point requires `!ends_with_newline`, which guarantees at least one interior row
    // exists before the trailing fragment (the empty-interior case already returned
    // `SealAndRoll` above, when `seek_pos > 0` and `rows.len() <= 1`, or was excluded by
    // the `newline_positions.is_empty()` check).
    let Some(anchor_line) = second_last else {
        // Can't happen per the invariant above, but never panic on a recovery path.
        return Ok(TailOutcome::SealAndRoll {
            reason: SealReason::Unparseable,
            claimed_last_id: None,
            failure_offset: last_start,
        });
    };
    let anchor = match check_row(anchor_line) {
        RowCheck::Verified(event) => Some((event.id + 1, event.row_hash)),
        RowCheck::HashMismatch(_) | RowCheck::Unparseable => None,
    };

    match anchor {
        Some((next_id, prev_hash)) => Ok(TailOutcome::TruncateContinue {
            keep_len: last_start,
            next_id,
            prev_hash,
            bytes_discarded: last_end - last_start,
            discard_offset: last_start,
        }),
        None => Ok(TailOutcome::SealAndRoll {
            reason: SealReason::Unparseable,
            claimed_last_id: None,
            failure_offset: last_start,
        }),
    }
}

/// Truncates the audit file to `keep_len` (discarding a torn tail write) and appends an
/// `audit:torn-write-recovered` sentinel as the first event of this session, joining the
/// hash chain normally.
///
/// Invariant: `keep_len` always came from `classify_tail` as the byte offset immediately
/// after the last row that both parsed and verified — a verified row is never removed.
fn truncate_and_continue(
    path: &Path,
    keep_len: u64,
    next_id: i64,
    prev_hash: [u8; 32],
    bytes_discarded: u64,
    discard_offset: u64,
) -> KResult<(i64, [u8; 32])> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot open log file for truncation {}: {e}",
                path.display()
            ))
        })?;
    file.set_len(keep_len)
        .map_err(|e| KmsError::ServerError(format!("audit: cannot truncate log file: {e}")))?;
    drop(file);

    error!(
        "AuditFileStore: torn write recovered — discarded {bytes_discarded} byte(s) at offset \
         {discard_offset} (process likely killed mid-write); resuming chain at id={next_id}"
    );

    let mut sink = open_append(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot reopen log file after truncation {}: {e}",
            path.display()
        ))
    })?;

    let details = serde_json::json!({
        "bytes_discarded": bytes_discarded,
        "offset": discard_offset,
    })
    .to_string();
    let draft = AuditEventDraft {
        timestamp: OffsetDateTime::now_utc(),
        operation: "audit:torn-write-recovered".to_owned(),
        user: "server".to_owned(),
        object_uid: None,
        algorithm: None,
        client_ip: None,
        result: AuditResult::Success,
        duration_ms: 0,
        request_id: None,
        details: Some(details),
    };
    let mut chain_prev_hash = prev_hash;
    let final_next_id = write_draft_to_chain(&mut sink, draft, next_id, &mut chain_prev_hash);

    Ok((final_next_id, chain_prev_hash))
}

/// Builds the sealed filename for a corrupted audit log: `<stem>.<RFC3339-compact
/// UTC>.<8 hex>.corrupt.<ext>`. The timestamp gives lexicographic chronological ordering
/// across sealed files; the trailing hex resolves same-second collisions.
fn sealed_file_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("audit");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("jsonl");
    let now = OffsetDateTime::now_utc();
    let ts = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    // Collision-avoidance only, not security-sensitive — derived from a fresh UUID
    // instead of pulling in a dedicated RNG crate.
    let suffix = hex::encode(&uuid::Uuid::new_v4().as_bytes()[..4]);
    path.with_file_name(format!("{stem}.{ts}.{suffix}.corrupt.{ext}"))
}

/// Seals a corrupted/tampered audit file aside as forensic evidence and starts a fresh
/// chain at `path`.
///
/// Order is load-bearing: the old file is renamed **before** the fresh one is opened, so
/// the lock holder never observes a half-migrated state (rename, then open — never the
/// reverse).
fn seal_and_roll(
    path: &Path,
    reason: SealReason,
    claimed_last_id: Option<i64>,
    failure_offset: u64,
) -> KResult<(i64, [u8; 32])> {
    let (sha256_hex, size) = cosmian_kms_access::audit::sha256_file(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot read log file to seal {}: {e}",
            path.display()
        ))
    })?;

    let sealed_path = sealed_file_path(path);
    std::fs::rename(path, &sealed_path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot seal corrupted log file {} -> {}: {e}",
            path.display(),
            sealed_path.display()
        ))
    })?;

    error!(
        "AuditFileStore: sealed corrupted audit log as {} (reason={}, sha256={sha256_hex}, \
         size={size}, claimed_last_id={claimed_last_id:?}, failure_offset={failure_offset}) — \
         starting a fresh chain",
        sealed_path.display(),
        reason.as_str(),
    );

    // fsync the containing directory so the rename itself is durable.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            drop(dir.sync_all());
        }
    }

    let mut sink = open_append(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot open fresh log file {}: {e}",
            path.display()
        ))
    })?;

    let sealed_name = sealed_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let details = serde_json::json!({
        "sealed_file": sealed_name,
        "sha256": sha256_hex,
        "size": size,
        "claimed_last_id": claimed_last_id,
        "failure_offset": failure_offset,
        "reason": reason.as_str(),
    })
    .to_string();
    let draft = AuditEventDraft {
        timestamp: OffsetDateTime::now_utc(),
        operation: "audit:reanchor".to_owned(),
        user: "server".to_owned(),
        object_uid: None,
        algorithm: None,
        client_ip: None,
        result: AuditResult::Success,
        duration_ms: 0,
        request_id: None,
        details: Some(details),
    };

    // Reanchor is a new chain root — continuity across a sealed, untrusted tail is never
    // asserted (see module docs).
    let mut prev_hash = [0_u8; 32];
    let next_id = write_draft_to_chain(&mut sink, draft, 0, &mut prev_hash);

    Ok((next_id, prev_hash))
}

/// Abstraction over the audit log's underlying writer.
///
/// This exists so the fault path (`write_event` failing mid-run) can be
/// exercised in tests with a mock sink, without touching real files —
/// production always uses `std::fs::File`.
trait AuditSink {
    /// Serialises and durably persists one event.
    ///
    /// # Errors
    /// On failure, the caller must NOT consider the event committed: it does
    /// not advance the chain's `next_id`/`prev_hash`, so the same slot is
    /// reused by the next successfully written event.
    fn write_event(&mut self, event: &AuditEvent) -> std::io::Result<()>;

    /// Called once when the writer loop exits (channel closed). Default is a
    /// no-op.
    fn final_sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AuditSink for std::fs::File {
    /// Serialises `event` as a single JSONL line and syncs to storage.
    ///
    /// `sync_data()` is called on every write to guarantee durability: without it
    /// data sits in the kernel page cache and is lost on a power failure.  The
    /// tradeoff is one `fsync` per audit event; high-throughput deployments can
    /// reduce cost by batching syncs (every N events or every T ms).
    fn write_event(&mut self, event: &AuditEvent) -> std::io::Result<()> {
        serde_json::to_writer(&mut *self, event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.write_all(b"\n")?;
        self.sync_data()
    }

    fn final_sync(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }
}

/// How long to wait between attempts to acquire the exclusive audit-log lock while a
/// peer instance (e.g. the other side of a rolling update on a shared volume) holds it.
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// How long to wait between attempts to recover/open the audit log after a
/// content-independent I/O fault (EACCES, EIO, read-only mount, missing disk).
const OPEN_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Builds the sidecar lock file path for `path`, e.g. `audit.jsonl` -> `audit.jsonl.lock`.
fn lock_file_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(OsString::new, OsStr::to_os_string);
    name.push(".lock");
    path.with_file_name(name)
}

/// Attempts to acquire the exclusive, cross-platform advisory lock on `path`'s lock
/// sidecar. Non-blocking: returns immediately (`Err` if another live instance holds it).
///
/// The returned `File` must be kept alive for as long as the lock should be held — the OS
/// releases it automatically when the handle is dropped or the process exits, so a crash
/// never leaves a stale lock behind.
fn try_acquire_lock(lock_path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    if fs4::fs_std::FileExt::try_lock_exclusive(&file)? {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "audit log lock is held by another instance",
        ))
    }
}

/// Scans every row of the audit log except the last one, checking both `verify_event`
/// and the chain link to the previous row. Runs unconditionally on every boot — this is
/// the only way an interior break (e.g. a middle row tampered in place) is ever caught,
/// since `classify_tail`'s tail-window read cannot see it.
///
/// The last row is deliberately never checked here: its fate (resume / torn-write /
/// seal-at-tail) is `classify_tail`'s job alone, and applying this function's stricter
/// "any defect seals the file" rule to it would misclassify an ordinary torn write (an
/// interrupted, incomplete last line) as tampering.
///
/// Streams the file line-by-line (`BufReader`) rather than loading it into memory, so
/// this stays cheap in both time and memory even for a large, long-lived log.
///
/// Returns the penultimate verified event when every interior row verifies, or the first
/// broken interior row's recovery metadata.
///
/// # Errors
/// Returns an error only if the file cannot be opened or read.
fn verify_interior_chain(path: &Path) -> KResult<InteriorChainOutcome> {
    if !path.exists() {
        return Ok(InteriorChainOutcome::Valid {
            previous_event: None,
        });
    }

    let file = std::fs::File::open(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot open log file for startup verification: {e}"
        ))
    })?;
    let reader = std::io::BufReader::new(file);

    let mut prev: Option<AuditEvent> = None;
    // One-line lookback: a line is only checked once we know a following line exists,
    // which is exactly what makes it an interior row and not the (unchecked) last one.
    let mut pending: Option<(String, u64)> = None;
    let mut offset: u64 = 0;

    for line in std::io::BufRead::lines(reader) {
        let line = line.map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot read log file for startup verification: {e}"
            ))
        })?;
        // `.lines()` strips the trailing '\n'; every interior line was terminated by one.
        let consumed = u64::try_from(line.len()).unwrap_or(u64::MAX) + 1;
        let line_offset = offset;
        offset += consumed;

        if let Some((pending_line, pending_offset)) = pending.take() {
            if !pending_line.trim().is_empty() {
                match check_row(&pending_line) {
                    RowCheck::Verified(event) => {
                        if verify_chain_link(&event, prev.as_ref()) {
                            prev = Some(event);
                        } else {
                            return Ok(InteriorChainOutcome::Broken {
                                reason: SealReason::HashMismatch,
                                claimed_last_id: Some(event.id),
                                failure_offset: pending_offset,
                            });
                        }
                    }
                    RowCheck::HashMismatch(event) => {
                        return Ok(InteriorChainOutcome::Broken {
                            reason: SealReason::HashMismatch,
                            claimed_last_id: Some(event.id),
                            failure_offset: pending_offset,
                        });
                    }
                    RowCheck::Unparseable => {
                        return Ok(InteriorChainOutcome::Broken {
                            reason: SealReason::Unparseable,
                            claimed_last_id: prev.as_ref().map(|p| p.id),
                            failure_offset: pending_offset,
                        });
                    }
                }
            }
        }
        pending = Some((line, line_offset));
    }

    Ok(InteriorChainOutcome::Valid {
        previous_event: prev,
    })
}

/// Runs an interior-chain integrity scan (unconditional, every boot) plus tail
/// classification and any required recovery (line-terminator repair, truncate-and-
/// continue, or seal-and-roll), then opens the file for the writer loop.
///
/// Only ever called after the exclusive lock is held — the peer's tail would otherwise be
/// a moving target.
///
/// A break found anywhere in the interior of the chain (never the last row — see
/// `verify_interior_chain`) routes straight to seal-and-roll.
///
/// # Errors
/// Returns an error only for content-independent I/O faults (cannot read/truncate/rename/
/// open); a data-corruption condition is always routed to a `TailOutcome` variant instead
/// and handled without error (see `classify_tail`).
fn recover_and_open(
    path: &Path,
) -> KResult<(std::fs::File, i64, [u8; 32])> {
    let (next_id, prev_hash) = match verify_interior_chain(path)? {
        InteriorChainOutcome::Broken {
            reason,
            claimed_last_id,
            failure_offset,
        } => {
            seal_and_roll(path, reason, claimed_last_id, failure_offset)?
        }
        InteriorChainOutcome::Valid { previous_event } => {
            match classify_tail(path, previous_event.as_ref())? {
                TailOutcome::Genesis => (0, [0_u8; 32]),
                TailOutcome::Resume {
                    next_id,
                    prev_hash,
                    needs_leading_nl,
                } => {
                    if needs_leading_nl {
                        // The prior process wrote the JSON row but crashed before its trailing
                        // '\n' hit disk. The row itself is valid — just fix the line boundary
                        // before the writer task appends anything new.
                        let mut f = open_append(path).map_err(|e| {
                            KmsError::ServerError(format!(
                                "audit: cannot repair missing line terminator in {}: {e}",
                                path.display()
                            ))
                        })?;
                        f.write_all(b"\n").map_err(|e| {
                            KmsError::ServerError(format!(
                                "audit: cannot repair missing line terminator in {}: {e}",
                                path.display()
                            ))
                        })?;
                        f.sync_data().map_err(|e| {
                            KmsError::ServerError(format!(
                                "audit: cannot sync line-terminator repair in {}: {e}",
                                path.display()
                            ))
                        })?;
                    } else {
                        debug!(
                            "AuditFileStore: resuming at id={next_id}, prev_hash={}",
                            hex::encode(&prev_hash[..8]) // first 8 bytes (16 hex chars) sufficient for diagnostics
                        );
                    }
                    (next_id, prev_hash)
                }
                TailOutcome::TruncateContinue {
                    keep_len,
                    next_id,
                    prev_hash,
                    bytes_discarded,
                    discard_offset,
                } => truncate_and_continue(
                    path,
                    keep_len,
                    next_id,
                    prev_hash,
                    bytes_discarded,
                    discard_offset,
                )?,
                TailOutcome::SealAndRoll {
                    reason,
                    claimed_last_id,
                    failure_offset,
                } => seal_and_roll(path, reason, claimed_last_id, failure_offset)?,
            }
        }
    };

    let file = open_append(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot open log file {}: {e}",
            path.display()
        ))
    })?;

    Ok((file, next_id, prev_hash))
}

/// Supervises the writer's lifecycle so the KMS always starts, regardless of the audit
/// log's state: acquires the exclusive lock (retrying in the background, without draining
/// the channel, if a peer holds it), recovers/opens the file (retrying if the path is
/// unwritable — EACCES, EIO, a read-only mount — so audit logging self-heals the moment
/// the fault clears), then runs the normal `writer_loop`.
///
/// Events enqueued while waiting for either step are genuinely queued in the channel and
/// flushed in order once the writer proceeds — they are not dropped. Only a channel that
/// fills to capacity during the wait spills to drop + eviction-sentinel, exactly like
/// saturation during normal operation.
async fn writer_supervisor(
    path: PathBuf,
    rx: mpsc::Receiver<WriterMsg>,
    dropped_count: Arc<AtomicU64>,
) {
    let lock_path = lock_file_path(&path);
    let mut lock_contended_logged = false;
    let _lock = loop {
        match try_acquire_lock(&lock_path) {
            Ok(lock) => break lock,
            Err(e) => {
                if lock_contended_logged {
                    debug!(
                        "AuditFileStore: still waiting on audit log lock {} ({e})",
                        lock_path.display()
                    );
                } else {
                    error!(
                        "AuditFileStore: audit log lock {} held by another instance ({e}) — \
                         buffering events until it is released",
                        lock_path.display()
                    );
                    lock_contended_logged = true;
                }
                tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
            }
        }
    };

    let (sink, next_id, prev_hash) = loop {
        match recover_and_open(&path) {
            Ok(triple) => break triple,
            Err(e) => {
                error!(
                    "AuditFileStore: cannot open audit log {} ({e}) — retrying",
                    path.display()
                );
                tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
            }
        }
    };

    writer_loop(sink, next_id, prev_hash, rx, dropped_count).await;
}

/// The background writer task.  Sole owner of the sink, the id counter, and
/// `prev_hash`.  Designed not to panic — errors are logged and the loop
/// continues.  Calls `final_sync()` before exiting so in-flight events are
/// durable on graceful shutdown.  Returns the sink so tests can inspect what
/// was actually persisted.
async fn writer_loop<S: AuditSink>(
    mut sink: S,
    mut next_id: i64,
    mut prev_hash: [u8; 32],
    mut rx: mpsc::Receiver<WriterMsg>,
    dropped_count: Arc<AtomicU64>,
) -> S {
    while let Some(msg) = rx.recv().await {
        let draft = match msg {
            WriterMsg::Event(draft) => *draft,
            WriterMsg::Flush(ack) => {
                // Every prior message has already been written above; simply
                // acknowledge. Ignore a dropped receiver (caller stopped waiting).
                let _ = ack.send(());
                continue;
            }
        };
        // Emit a sentinel before the real event if any drops occurred since the last write.
        let n_dropped = dropped_count.swap(0, Ordering::Relaxed);
        if n_dropped > 0 {
            let sentinel = make_eviction_sentinel(n_dropped);
            next_id = write_draft_to_chain(&mut sink, sentinel, next_id, &mut prev_hash);
        }
        next_id = write_draft_to_chain(&mut sink, draft, next_id, &mut prev_hash);
    }

    // Channel closed (sender dropped on graceful shutdown): ensure all written
    // events are durable before the task exits.
    if let Err(e) = sink.final_sync() {
        error!("AuditFileStore: final sync failed: {e}");
    }
    debug!("AuditFileStore: writer loop exited (channel closed)");
    sink
}

/// Finalises and writes a single `AuditEventDraft` into the chain, advancing
/// `next_id` and `prev_hash` on success.  Returns the new `next_id`.
fn write_draft_to_chain<S: AuditSink>(
    sink: &mut S,
    draft: AuditEventDraft,
    next_id: i64,
    prev_hash: &mut [u8; 32],
) -> i64 {
    let mut ev = AuditEvent {
        id: next_id,
        timestamp: draft.timestamp,
        operation: draft.operation,
        user: draft.user,
        object_uid: draft.object_uid,
        algorithm: draft.algorithm,
        client_ip: draft.client_ip,
        result: draft.result,
        duration_ms: draft.duration_ms,
        request_id: draft.request_id,
        details: draft.details,
        prev_hash: *prev_hash,
        row_hash: [0_u8; 32],
    };
    ev.row_hash = compute_row_hash(&ev);

    match sink.write_event(&ev) {
        Ok(()) => {
            *prev_hash = ev.row_hash;
            next_id.checked_add(1).unwrap_or_else(|| {
                error!(
                    "AuditFileStore: id counter overflow at i64::MAX — \
                     audit logging stopped. Rotate the log file and restart."
                );
                next_id
            })
        }
        Err(e) => {
            error!(
                "AuditFileStore: failed to write event id={}: {e} — event dropped",
                ev.id
            );
            // Do NOT advance id or prev_hash — the next event will reuse
            // the same slot, preserving chain continuity.
            next_id
        }
    }
}

/// Builds a sentinel `AuditEventDraft` that records how many real events were
/// dropped due to channel saturation.  Joins the hash chain like any real event
/// — detectable by `ckms audit verify` and compliance tooling.
fn make_eviction_sentinel(n_dropped: u64) -> AuditEventDraft {
    AuditEventDraft {
        timestamp: OffsetDateTime::now_utc(),
        operation: "audit:eviction".to_owned(),
        user: "server".to_owned(),
        object_uid: None,
        algorithm: None,
        client_ip: None,
        result: AuditResult::Failure(format!("{n_dropped} events dropped (channel full)")),
        duration_ms: 0,
        request_id: None,
        details: None,
    }
}

/// Opens the audit file for appending, creating parent directories if needed.
fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Builds an `AuditEventDraft` for a successful KMIP operation.
// Each parameter maps 1-to-1 to an `AuditEventDraft` field; a wrapper struct
// would not reduce the count and would require updating all call sites.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_success_draft(
    timestamp: OffsetDateTime,
    operation: impl Into<String>,
    user: impl Into<String>,
    object_uid: Option<String>,
    algorithm: Option<String>,
    client_ip: Option<String>,
    duration_ms: u64,
) -> AuditEventDraft {
    AuditEventDraft {
        timestamp,
        operation: operation.into(),
        user: user.into(),
        object_uid,
        algorithm,
        client_ip,
        result: AuditResult::Success,
        duration_ms,
        request_id: None,
        details: None,
    }
}

/// Builds an `AuditEventDraft` for a failed KMIP operation.
// Each parameter maps 1-to-1 to an `AuditEventDraft` field plus a `reason`
// string; a wrapper struct would not reduce the count.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_failure_draft(
    timestamp: OffsetDateTime,
    operation: impl Into<String>,
    user: impl Into<String>,
    object_uid: Option<String>,
    algorithm: Option<String>,
    client_ip: Option<String>,
    duration_ms: u64,
    reason: impl Into<String>,
) -> AuditEventDraft {
    AuditEventDraft {
        timestamp,
        operation: operation.into(),
        user: user.into(),
        object_uid,
        algorithm,
        client_ip,
        result: AuditResult::Failure(reason.into()),
        duration_ms,
        request_id: None,
        details: None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::{
        io::BufRead as _,
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicU64},
    };

    use cosmian_kms_access::audit::{
        AuditEvent, AuditEventDraft, compute_row_hash, verify_event,
    };
    use time::OffsetDateTime;
    use tokio::sync::mpsc;

    use super::{
        AuditFileStore, AuditSink, WriterMsg, lock_file_path, make_success_draft, writer_loop,
    };

    /// Small channel capacity used in all tests.  Large enough for the ≤5-event
    /// functional tests; small enough to fill quickly in the saturation test.
    const TEST_CAPACITY: usize = 16;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kms_audit_test_{}_{label}.jsonl",
            std::process::id()
        ))
    }

    fn make_draft() -> AuditEventDraft {
        make_success_draft(
            OffsetDateTime::now_utc(),
            "Encrypt",
            "alice",
            Some("obj-1".to_owned()),
            Some("AES-256-GCM".to_owned()),
            Some("127.0.0.1".to_owned()),
            5,
        )
    }

    fn read_events(path: &Path) -> Vec<AuditEvent> {
        let file = std::fs::File::open(path).unwrap();
        std::io::BufReader::new(file)
            .lines()
            .filter_map(|l| {
                let l = l.unwrap();
                if l.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str::<AuditEvent>(&l).unwrap())
                }
            })
            .collect()
    }

    fn assert_valid_chain(events: &[AuditEvent]) {
        for ev in events {
            assert!(verify_event(ev), "id={} has invalid row_hash", ev.id);
        }
        for w in events.windows(2) {
            if let [prev, curr] = w {
                assert_eq!(
                    curr.prev_hash, prev.row_hash,
                    "chain broken between id={} and id={}",
                    prev.id, curr.id
                );
            }
        }
    }

    /// On a current-thread runtime (the default for `#[tokio::test]`) the writer
    /// task does not run until we yield.  Sending 2× capacity synchronously fills
    /// the channel; the second half is dropped without blocking or panicking.
    #[tokio::test]
    async fn enqueue_drops_when_channel_full() {
        let path = temp_path("capacity");
        std::fs::remove_file(&path).ok();

        let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
        for _ in 0..(TEST_CAPACITY * 2) {
            store.enqueue(std::iter::once(make_draft()));
        }
        // Deterministic drain barrier instead of a fixed sleep: once flush()
        // returns, every event enqueued above has been written (and synced).
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        // most one sentinel for the dropped half, so the total is at most
        // TEST_CAPACITY + 1.  Crucially, it must be strictly less than
        // TEST_CAPACITY * 2 (confirming that drops occurred).
        assert!(
            events.len() <= TEST_CAPACITY + 1,
            "at most TEST_CAPACITY + 1 events (real + sentinel); got {}",
            events.len()
        );
        assert!(
            events.len() < TEST_CAPACITY * 2,
            "some events must have been dropped; got {} (none dropped?)",
            events.len()
        );
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// When the channel fills and a later event is enqueued, the writer emits a
    /// sentinel `audit:eviction` event in the chain before the next real event.
    #[tokio::test]
    async fn sentinel_emitted_after_drops() {
        let path = temp_path("sentinel");
        std::fs::remove_file(&path).ok();

        let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
        // Saturate: send 2× capacity so the second half is dropped.
        for _ in 0..(TEST_CAPACITY * 2) {
            store.enqueue(std::iter::once(make_draft()));
        }
        // One more real event — the writer will emit the sentinel first.
        store.enqueue(std::iter::once(make_draft()));
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert_valid_chain(&events);

        let sentinel = events
            .iter()
            .find(|e| e.operation == "audit:eviction")
            .expect("expected an audit:eviction sentinel event");
        // Sentinel result must be Failure with the drop count.
        match &sentinel.result {
            cosmian_kms_access::audit::AuditResult::Failure(msg) => {
                assert!(
                    msg.contains("dropped"),
                    "sentinel reason should mention 'dropped': {msg}"
                );
            }
            cosmian_kms_access::audit::AuditResult::Success => {
                panic!("expected Failure, got Success")
            }
        }

        std::fs::remove_file(&path).ok();
    }

    /// Write events across two store lifetimes and verify the chain is seamless.
    #[tokio::test]
    async fn chain_resumes_on_restart() {
        let path = temp_path("resume");
        std::fs::remove_file(&path).ok();

        // Phase 1: write 3 events
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            for _ in 0..3 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }

        // Phase 2: resume from the same file, write 2 more
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            for _ in 0..2 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }

        let events = read_events(&path);
        assert_eq!(events.len(), 5, "expected 5 total events after restart");
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(
                ev.id,
                i64::try_from(i).unwrap(),
                "id must be sequential across restart"
            );
        }
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// Verifies that after a sequence of successful writes the ids are strictly
    /// sequential and all chain links are valid.  Mid-run write failures are
    /// covered directly by `faulty_sink_error_does_not_advance_chain_and_reuses_slot`.
    #[tokio::test]
    async fn write_failure_does_not_advance_chain() {
        let path = temp_path("no_advance");
        std::fs::remove_file(&path).ok();

        let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
        for _ in 0..5 {
            store.enqueue(std::iter::once(make_draft()));
        }
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert_eq!(events.len(), 5);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev.id, i64::try_from(i).unwrap(), "id gap at position {i}");
        }
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// `start()` must never abort on a tampered last event — a complete row whose hash
    /// doesn't match its own bytes is structurally distinct from a torn write, so it is
    /// routed to seal-and-roll: the old file is sealed aside as evidence and a fresh
    /// chain (a reanchor row) starts at the original path.
    #[tokio::test]
    async fn resume_seals_and_rolls_tampered_last_line() {
        let path = temp_path("tampered");
        std::fs::remove_file(&path).ok();

        // Write 2 valid events
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }

        // Overwrite the file with the last event's row_hash zeroed out
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        let mut last_ev: AuditEvent = serde_json::from_str(lines.last().unwrap()).unwrap();
        last_ev.row_hash = [0_u8; 32];
        *lines.last_mut().unwrap() = serde_json::to_string(&last_ev).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let store = AuditFileStore::start(&path, TEST_CAPACITY)
            .expect("start() must always succeed, even on a tampered log tail");
        store.flush().await;
        drop(store);

        let sealed = find_sealed_file(&path);
        assert!(sealed.is_some(), "expected a *.corrupt.jsonl sealed file");

        let events = read_events(&path);
        assert_eq!(
            events.len(),
            1,
            "fresh chain must start with just the reanchor row"
        );
        assert_eq!(events[0].id, 0);
        assert_eq!(events[0].prev_hash, [0_u8; 32]);
        assert_eq!(events[0].operation, "audit:reanchor");
        let details = events[0].details.as_deref().unwrap_or_default();
        assert!(details.contains("hash_mismatch"), "details: {details}");
        assert!(
            details.contains(
                &sealed
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            ),
            "details must name the sealed file: {details}"
        );

        std::fs::remove_file(&path).ok();
        cleanup_sealed_files(&path);
    }

    /// The final row must link to its predecessor even when its own row hash was
    /// recomputed after tampering. The interior scan intentionally skips the physical
    /// tail to preserve torn-write recovery, so `classify_tail` enforces this link.
    #[tokio::test]
    async fn resume_seals_and_rolls_last_row_with_broken_chain_link() {
        let path = temp_path("last_link_tamper");
        std::fs::remove_file(&path).ok();

        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        let last_index = lines.len() - 1;
        let mut last_event: AuditEvent = serde_json::from_str(&lines[last_index]).unwrap();
        last_event.prev_hash = [0xA5; 32];
        last_event.row_hash = compute_row_hash(&last_event);
        lines[last_index] = serde_json::to_string(&last_event).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
        store.flush().await;
        drop(store);

        assert!(
            find_sealed_file(&path).is_some(),
            "a final row with a broken prev_hash link must be sealed"
        );
        let events = read_events(&path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "audit:reanchor");

        std::fs::remove_file(&path).ok();
        cleanup_sealed_files(&path);
    }

    // ── Always-start: lock contention and self-healing ────────────────────

    /// An unwritable path (here: a path that walks *through* an existing plain file,
    /// deterministic on every platform/CI user unlike relying on permissions, which root
    /// ignores) must never abort startup. `start()` succeeds immediately; the writer
    /// keeps retrying in the background and self-heals the moment the fault clears.
    #[tokio::test]
    async fn start_self_heals_after_unwritable_path_is_fixed() {
        let blocker = temp_path("unopenable_blocker");
        std::fs::remove_file(&blocker).ok();
        std::fs::write(&blocker, b"i am a file, not a directory").unwrap();
        // `blocker` is a file, so treating it as a parent directory fails until removed.
        let bogus_path = blocker.join("audit.jsonl");

        let store = AuditFileStore::start(&bogus_path, TEST_CAPACITY)
            .expect("start() must always succeed, even for an unwritable path");

        // While broken, enqueued events are dropped (logged), never causing a panic.
        store.enqueue(std::iter::once(make_draft()));

        // Fix the fault — the writer must notice on its next retry and self-heal.
        std::fs::remove_file(&blocker).ok();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            store.enqueue(std::iter::once(make_draft()));
            if bogus_path.exists() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer never self-healed after the fault was fixed"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        store.flush().await;

        let events = read_events(&bogus_path);
        assert!(
            !events.is_empty(),
            "expected at least one persisted event after self-heal"
        );

        std::fs::remove_file(&bogus_path).ok();
        cleanup_sealed_files(&bogus_path);
    }

    /// While a peer instance holds the exclusive lock, the writer must not touch the
    /// file at all — events are buffered in the channel, not dropped, and flushed in
    /// order once the lock is released and acquired.
    #[tokio::test]
    async fn lock_contention_buffers_until_released() {
        let path = temp_path("lock_contention");
        std::fs::remove_file(&path).ok();

        let lock_path = lock_file_path(&path);
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        fs4::fs_std::FileExt::try_lock_exclusive(&held).unwrap();

        let store = AuditFileStore::start(&path, TEST_CAPACITY)
            .expect("start() must always succeed even when the lock is held by a peer");

        store.enqueue(std::iter::once(make_draft()));
        store.enqueue(std::iter::once(make_draft()));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !path.exists(),
            "must not write anything while the lock is held by a peer"
        );

        // Release the peer's lock — the writer should acquire it and flush the buffer.
        fs4::fs_std::FileExt::unlock(&held).ok();
        drop(held);

        store.flush().await;
        let events = read_events(&path);
        assert_eq!(
            events.len(),
            2,
            "buffered events must be flushed once the lock is acquired"
        );
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&lock_path).ok();
    }

    /// A zero channel capacity is rejected before any file I/O or task spawn.
    #[test]
    fn start_fails_with_zero_capacity() {
        let path = temp_path("zero_capacity");
        std::fs::remove_file(&path).ok();

        let result = AuditFileStore::start(&path, 0);
        assert!(result.is_err(), "start() must reject channel_capacity == 0");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("channel_capacity must be at least 1"),
            "unexpected error message: {err}"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A last line that isn't valid JSON at all, but the file DOES end in `\n` (a complete,
    /// terminated, garbage row — not an interrupted write), must seal-and-roll rather than
    /// abort startup.
    #[tokio::test]
    async fn start_seals_and_rolls_malformed_last_line() {
        let path = temp_path("malformed_last_line");
        std::fs::remove_file(&path).ok();
        std::fs::write(&path, b"{not valid json at all\n").unwrap();

        let store = AuditFileStore::start(&path, TEST_CAPACITY)
            .expect("start() must always succeed, even on structural garbage");
        store.flush().await;
        drop(store);

        let sealed = find_sealed_file(&path);
        assert!(sealed.is_some(), "expected a *.corrupt.jsonl sealed file");

        let events = read_events(&path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "audit:reanchor");
        let details = events[0].details.as_deref().unwrap_or_default();
        assert!(details.contains("unparseable"), "details: {details}");

        std::fs::remove_file(&path).ok();
        cleanup_sealed_files(&path);
    }

    /// Interior-chain verification runs unconditionally on every boot, so it catches a
    /// mid-chain tamper that `classify_tail`'s tail-window read alone cannot see (the
    /// last row is untouched and still verifies fine in isolation).
    #[tokio::test]
    async fn startup_always_catches_mid_chain_tamper() {
        let path = temp_path("interior_verify");
        std::fs::remove_file(&path).ok();

        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            for _ in 0..3 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }

        // Tamper an EARLY row's content without touching its stored row_hash — the last
        // row is untouched and would look perfectly fine to a tail-only check.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        let mut row0: AuditEvent = serde_json::from_str(&lines[0]).unwrap();
        row0.operation = "Destroy".to_owned();
        lines[0] = serde_json::to_string(&row0).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let store = AuditFileStore::start(&path, TEST_CAPACITY)
            .expect("start() must always succeed, even on a mid-chain tamper");
        store.flush().await;
        drop(store);

        assert!(
            find_sealed_file(&path).is_some(),
            "a mid-chain tamper must always be caught and seal-and-rolled"
        );

        std::fs::remove_file(&path).ok();
        cleanup_sealed_files(&path);
    }

    /// Finds the `*.corrupt.<ext>` sibling file sealed next to `path`, if any.
    fn find_sealed_file(path: &Path) -> Option<PathBuf> {
        let parent = path.parent()?;
        let stem = path.file_stem()?.to_string_lossy().into_owned();
        std::fs::read_dir(parent)
            .ok()?
            .filter_map(Result::ok)
            .find_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                (name.starts_with(&stem) && name.contains(".corrupt.")).then(|| entry.path())
            })
    }

    /// Removes every `*.corrupt.<ext>` sibling of `path` left behind by a test.
    fn cleanup_sealed_files(path: &Path) {
        while let Some(sealed) = find_sealed_file(path) {
            std::fs::remove_file(&sealed).ok();
        }
    }

    /// A torn (interrupted) write — an incomplete trailing fragment with no terminating
    /// `\n` — is truncated away and the chain continues in place, with a
    /// `audit:torn-write-recovered` sentinel as the next event. No prior verified row is
    /// ever removed.
    #[tokio::test]
    async fn torn_write_truncates_and_continues() {
        let path = temp_path("torn");
        std::fs::remove_file(&path).ok();

        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }
        let before = read_events(&path);
        assert_eq!(before.len(), 2);

        // Simulate a crash mid-write: append an incomplete JSON fragment, no trailing '\n'.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            write!(f, "{{\"id\":2,\"timestamp\":\"broken-mid-write").unwrap();
        }

        let store = AuditFileStore::start(&path, TEST_CAPACITY)
            .expect("start() must always succeed, even after a torn write");
        store.flush().await;
        drop(store);

        assert!(
            find_sealed_file(&path).is_none(),
            "a torn write must never seal-and-roll"
        );

        let events = read_events(&path);
        assert_eq!(events.len(), 3, "2 original + 1 torn-write sentinel");
        assert_eq!(events[0].id, before[0].id);
        assert_eq!(events[1].id, before[1].id);
        assert_eq!(events[2].operation, "audit:torn-write-recovered");
        assert_eq!(events[2].prev_hash, before[1].row_hash);
        assert_valid_chain(&events);

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("broken-mid-write"),
            "torn fragment must be discarded"
        );

        std::fs::remove_file(&path).ok();
    }

    /// A complete, verified last row missing only its trailing `\n` (crash between the
    /// JSON write and the newline write) is resumed in place, not truncated or sealed —
    /// the line boundary is repaired before the next append.
    #[tokio::test]
    async fn resume_repairs_missing_trailing_newline() {
        let path = temp_path("missing_nl");
        std::fs::remove_file(&path).ok();

        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }

        // Strip the final newline — the last row is complete and valid, just unterminated.
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.trim_end_matches('\n')).unwrap();

        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY)
                .expect("start() must always succeed on a missing trailing newline");
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }

        assert!(find_sealed_file(&path).is_none());

        let events = read_events(&path);
        assert_eq!(events.len(), 3, "2 original + 1 new event after resume");
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev.id, i64::try_from(i).unwrap());
        }
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    // ── Fault injection on the write path ────────────────────────────────

    /// A mock `AuditSink` that fails `write_event` for calls whose 0-based
    /// index satisfies `should_fail`, allowing precise control over exactly
    /// which write in a sequence fails.
    struct FaultySink {
        events: Vec<AuditEvent>,
        call_count: usize,
        should_fail: fn(usize) -> bool,
    }

    impl FaultySink {
        fn new(should_fail: fn(usize) -> bool) -> Self {
            Self {
                events: Vec::new(),
                call_count: 0,
                should_fail,
            }
        }
    }

    impl AuditSink for FaultySink {
        fn write_event(&mut self, event: &AuditEvent) -> std::io::Result<()> {
            let idx = self.call_count;
            self.call_count += 1;
            if (self.should_fail)(idx) {
                return Err(std::io::Error::other("simulated write failure"));
            }
            self.events.push(event.clone());
            Ok(())
        }
    }

    /// A single failed write mid-run must not advance the chain: the failed
    /// draft is lost, and the next successful write reuses its `id`/`prev_hash`
    /// slot — proving the "do not advance on failure" invariant that was
    /// previously only exercised on the happy path.
    #[tokio::test]
    async fn faulty_sink_error_does_not_advance_chain_and_reuses_slot() {
        let (tx, rx) = mpsc::channel::<WriterMsg>(TEST_CAPACITY);
        let dropped_count = Arc::new(AtomicU64::new(0));
        // Fail exactly the 3rd write call (0-based index 2).
        let sink = FaultySink::new(|idx| idx == 2);

        let handle = tokio::spawn(writer_loop(sink, 0, [0_u8; 32], rx, dropped_count));

        for _ in 0..5 {
            tx.send(WriterMsg::Event(Box::new(make_draft())))
                .await
                .unwrap();
        }
        drop(tx);

        let sink = handle.await.unwrap();
        assert_eq!(
            sink.events.len(),
            4,
            "one of the 5 drafts must be lost to the injected write failure"
        );
        for (i, ev) in sink.events.iter().enumerate() {
            assert_eq!(
                ev.id,
                i64::try_from(i).unwrap(),
                "ids must stay contiguous — the failed write's slot must be reused, not skipped"
            );
        }
        assert_valid_chain(&sink.events);
    }

    /// When every write fails, nothing is persisted and the writer loop still
    /// exits cleanly (no panic) once the channel closes.
    #[tokio::test]
    async fn faulty_sink_all_writes_fail_persists_nothing() {
        let (tx, rx) = mpsc::channel::<WriterMsg>(TEST_CAPACITY);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let sink = FaultySink::new(|_| true);

        let handle = tokio::spawn(writer_loop(sink, 0, [0_u8; 32], rx, dropped_count));

        for _ in 0..3 {
            tx.send(WriterMsg::Event(Box::new(make_draft())))
                .await
                .unwrap();
        }
        drop(tx);

        let sink = handle.await.unwrap();
        assert!(
            sink.events.is_empty(),
            "no event should be persisted when every write fails"
        );
    }
}
