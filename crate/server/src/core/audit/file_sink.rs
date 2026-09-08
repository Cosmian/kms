//! Tamper-evident JSONL file persistence and startup recovery for the audit log.
//!
//! Hash chain
//! ==========
//! Each persisted row carries:
//!   `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
//!   `row_hash`  — SHA-256 of this row's canonical bytes (including `prev_hash`)
//!
//! Use `ckms audit verify --path <file>` to validate the chain offline.
//!
//! Always-start recovery
//! ======================
//! [`FileSink::resume`] guarantees the KMS always starts regardless of the audit log's
//! state: it acquires the exclusive lock and recovers/opens the file inside a
//! self-healing retry loop that never returns an error — the generic writer task simply
//! awaits it while events are buffered upstream in the channel, never blocking the caller.
//! Recovery is routed by cause (see `TailOutcome`) rather than one global policy: a torn
//! (interrupted) write is truncated and the chain resumes in place; a tampered or
//! structurally invalid row is sealed aside as forensic evidence and a fresh chain
//! starts.

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};

use async_trait::async_trait;
use cosmian_kms_access::audit::{
    AuditEvent, AuditEventDraft, AuditResult, verify_chain_link, verify_event,
};
use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
use cosmian_logger::{debug, error};
use time::OffsetDateTime;

use crate::{error::KmsError, result::KResult};

/// Bytes read from the end of an existing log to locate the last complete event
/// at startup.  64 KiB comfortably covers many events; a single serialised
/// `AuditEventFull` is typically <2 KiB.
const TAIL_WINDOW: u64 = 65_536;

/// How long to wait between attempts to acquire the exclusive audit-log lock while a
/// peer instance (e.g. the other side of a rolling update on a shared volume) holds it.
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// How long to wait between attempts to recover/open the audit log after a
/// content-independent I/O fault (EACCES, EIO, read-only mount, missing disk).
const OPEN_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Cross-task state for the optional `max_size_bytes` write-stop cap.
///
/// `enqueue()` reads `size_limit_reached` as a fast, non-blocking pre-check so a
/// caller doesn't bother queueing an event the writer will only ever discard; the
/// writer task is the sole owner of the file and the only one that ever sets it.
/// `max_size_bytes` is immutable for the store's lifetime, carried alongside so
/// the writer doesn't need it threaded through as a separate argument everywhere.
#[derive(Default)]
pub(super) struct AuditWriteState {
    pub(super) max_size_bytes: Option<u64>,
    pub(super) size_limit_reached: std::sync::atomic::AtomicBool,
}

impl AuditWriteState {
    pub(super) const fn new(max_size_bytes: Option<u64>) -> Self {
        Self {
            max_size_bytes,
            size_limit_reached: std::sync::atomic::AtomicBool::new(false),
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
    /// A valid, verified row whose `id` is `i64::MAX` — incrementing it for the next
    /// event would overflow, so recovery cannot safely resume the chain in place.
    IdOverflow,
}

impl SealReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash_mismatch",
            Self::Unparseable => "unparseable",
            Self::IdOverflow => "id_overflow",
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

/// Metadata for the first invalid interior row.
struct InteriorChainFailure {
    reason: SealReason,
    claimed_last_id: Option<i64>,
    failure_offset: u64,
}

/// Result of verifying every audit row except the physical tail row.
///
/// `previous_event` is the row the tail must link to when the tail is complete.
struct InteriorChainVerification {
    previous_event: Option<AuditEvent>,
    failure: Option<InteriorChainFailure>,
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
                match event.id.checked_add(1) {
                    Some(next_id) => TailOutcome::Resume {
                        next_id,
                        prev_hash: event.row_hash,
                        needs_leading_nl: false,
                    },
                    None => TailOutcome::SealAndRoll {
                        reason: SealReason::IdOverflow,
                        claimed_last_id: Some(event.id),
                        failure_offset: last_start,
                    },
                }
            }
            RowCheck::Verified(event) | RowCheck::HashMismatch(event) => TailOutcome::SealAndRoll {
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
        return Ok(if !verify_chain_link(&event, previous_event) {
            TailOutcome::SealAndRoll {
                reason: SealReason::HashMismatch,
                claimed_last_id: Some(event.id),
                failure_offset: last_start,
            }
        } else if let Some(next_id) = event.id.checked_add(1) {
            TailOutcome::Resume {
                next_id,
                prev_hash: event.row_hash,
                needs_leading_nl: true,
            }
        } else {
            TailOutcome::SealAndRoll {
                reason: SealReason::IdOverflow,
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
    match check_row(anchor_line) {
        RowCheck::Verified(event) => match event.id.checked_add(1) {
            Some(next_id) => Ok(TailOutcome::TruncateContinue {
                keep_len: last_start,
                next_id,
                prev_hash: event.row_hash,
                bytes_discarded: last_end - last_start,
                discard_offset: last_start,
            }),
            None => Ok(TailOutcome::SealAndRoll {
                reason: SealReason::IdOverflow,
                claimed_last_id: Some(event.id),
                failure_offset: last_start,
            }),
        },
        RowCheck::HashMismatch(_) | RowCheck::Unparseable => Ok(TailOutcome::SealAndRoll {
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
    let final_next_id = write_recovery_sentinel(&mut sink, draft, next_id, &mut chain_prev_hash);

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
    let next_id = write_recovery_sentinel(&mut sink, draft, 0, &mut prev_hash);

    Ok((next_id, prev_hash))
}

/// Serialises `event` as a single JSONL line and durably syncs it to `file`.
///
/// Shared by [`FileSink::write_event`] (steady-state, called from the async writer task)
/// and [`write_recovery_sentinel`] (recovery-time, called from a `spawn_blocking` context
/// with no async runtime available) so both paths write byte-identical rows.
///
/// `sync_data()` is called on every write to guarantee durability: without it data sits
/// in the kernel page cache and is lost on a power failure. The tradeoff is one `fsync`
/// per audit event; high-throughput deployments can reduce cost by batching syncs (every
/// N events or every T ms).
fn write_event_line(file: &mut std::fs::File, event: &AuditEvent) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(b"\n")?;
    file.sync_data()
}

/// Writes a synthetic recovery sentinel (torn-write-recovered / reanchor) directly to
/// `file`, advancing the chain on success and leaving it untouched on failure — mirroring
/// the writer loop's own "never advance on a failed write" rule.
///
/// A plain sync helper rather than a call through [`AuditSink`]: `recover_and_open` runs
/// inside `spawn_blocking`, before the async writer task (and its sink) exist at all.
fn write_recovery_sentinel(
    file: &mut std::fs::File,
    draft: AuditEventDraft,
    next_id: i64,
    prev_hash: &mut [u8; 32],
) -> i64 {
    let event = draft.finalize(next_id, *prev_hash);
    match write_event_line(file, &event) {
        Ok(()) => {
            *prev_hash = event.row_hash;
            next_id.checked_add(1).unwrap_or(next_id)
        }
        Err(e) => {
            error!(
                "AuditFileStore: failed to write recovery sentinel id={}: {e} — event dropped",
                event.id
            );
            next_id
        }
    }
}

/// The file-backed [`AuditSink`]: persists the audit chain as a tamper-evident JSONL file
/// with the always-start, self-healing recovery documented at the top of this module.
///
/// Historically (before this trait existed) a write failure was always logged and
/// skipped rather than treated as fatal — [`AuditSink::write_failure_is_fatal`] is
/// overridden to `false` to preserve that behaviour.
pub(crate) struct FileSink {
    path: PathBuf,
    write_state: Arc<AuditWriteState>,
    /// `None` until [`Self::resume`] has run; the trait contract guarantees `resume` is
    /// called exactly once before any `write_event`.
    file: Option<std::fs::File>,
    /// Held for the sink's entire lifetime — the OS releases it automatically on drop or
    /// process exit, so a crash never leaves a stale lock behind. Never read after
    /// acquisition; kept alive purely for its `Drop` behaviour.
    #[allow(dead_code, reason = "kept alive for its Drop impl, never read again")]
    lock: Option<std::fs::File>,
}

impl FileSink {
    /// Builds a not-yet-resumed file sink for `path`. `write_state` is shared with the
    /// `AuditStore` handle so `enqueue()`'s fast pre-check and this sink's own
    /// post-write cap update observe the same flag.
    pub(super) const fn new(path: PathBuf, write_state: Arc<AuditWriteState>) -> Self {
        Self {
            path,
            write_state,
            file: None,
            lock: None,
        }
    }
}

#[async_trait]
impl AuditSink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    /// Acquires the exclusive lock (retrying forever, without erroring, while a peer
    /// instance holds it) and recovers/opens the file (retrying forever on a
    /// content-independent I/O fault — EACCES, EIO, a read-only mount), self-healing the
    /// moment the fault clears. In practice this never returns `Err`: see the module docs
    /// for why the file backend always starts.
    ///
    /// # Errors
    /// The signature allows an error per the trait contract, but this implementation
    /// retries indefinitely instead of ever reporting one.
    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        let lock_path = lock_file_path(&self.path);
        let mut lock_contended_logged = false;
        let lock = loop {
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
        self.lock = Some(lock);

        let (file, next_id, prev_hash) = loop {
            // `recover_and_open` does blocking `std::fs` I/O (whole-file scan, hash, and
            // possible rename on seal-and-roll) — run it on the blocking pool so a large
            // audit log doesn't monopolize this tokio worker thread during recovery.
            let path_for_recovery = self.path.clone();
            let recovered =
                tokio::task::spawn_blocking(move || recover_and_open(&path_for_recovery)).await;
            match recovered {
                Ok(Ok(triple)) => break triple,
                Ok(Err(e)) => {
                    error!(
                        "AuditFileStore: cannot open audit log {} ({e}) — retrying",
                        self.path.display()
                    );
                    tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
                }
                Err(join_err) => {
                    error!("AuditFileStore: recovery task failed to run ({join_err}) — retrying");
                    tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
                }
            }
        };

        enforce_size_cap(&file, &self.write_state, &self.path);
        self.file = Some(file);
        Ok(ChainHead { next_id, prev_hash })
    }

    /// # Errors
    /// Returns an error if the sink has not been `resume()`d yet, or if the underlying
    /// write/sync fails. Neither ever advances the chain — see the trait contract.
    async fn write_event(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        let file = self.file.as_mut().ok_or_else(|| {
            InterfaceError::Default(
                "audit: FileSink::write_event called before resume()".to_owned(),
            )
        })?;
        write_event_line(file, event)
            .map_err(|e| InterfaceError::Default(format!("audit: write failed: {e}")))?;
        enforce_size_cap(file, &self.write_state, &self.path);
        Ok(())
    }

    /// Preserves the file backend's pre-trait behaviour: a write failure is logged and
    /// skipped, never fatal to the server.
    fn write_failure_is_fatal(&self) -> bool {
        false
    }

    fn is_write_capacity_exceeded(&self) -> bool {
        self.write_state.size_limit_reached.load(Ordering::Relaxed)
    }

    async fn final_sync(&mut self) -> InterfaceResult<()> {
        if let Some(file) = self.file.as_mut() {
            file.sync_data()
                .map_err(|e| InterfaceError::Default(format!("audit: final sync failed: {e}")))?;
        }
        Ok(())
    }
}

/// Checks `file`'s current on-disk length against `write_state.max_size_bytes` and
/// updates `write_state` on the first transition into the capped state (logging
/// once). Called right after the sink resumes/opens the file (an already-oversized log
/// must block immediately) and again after every successful write (a write that crosses
/// the cap is allowed to land, then blocks everything after it).
fn enforce_size_cap(file: &std::fs::File, write_state: &AuditWriteState, path: &Path) {
    let Some(cap) = write_state.max_size_bytes else {
        return;
    };
    let len = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(e) => {
            error!(
                "AuditFileStore: cannot stat audit log {} ({e})",
                path.display()
            );
            return;
        }
    };
    if len < cap {
        return;
    }
    let was_already_capped = write_state.size_limit_reached.swap(true, Ordering::Relaxed);
    if !was_already_capped {
        error!(
            "AuditFileStore: audit log {} reached its configured max_size_bytes cap \
             ({len} bytes >= {cap}) — audit writing is blocked until the log is safely \
             remediated and the KMS is restarted",
            path.display()
        );
    }
}

/// Opens the audit file for appending, creating parent directories if needed.
pub(super) fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Builds the sidecar lock file path for `path`, e.g. `audit.jsonl` -> `audit.jsonl.lock`.
pub(super) fn lock_file_path(path: &Path) -> PathBuf {
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
/// memory use stays constant even for a large, long-lived log (runtime is still linear in
/// the number of rows).
///
/// Returns the penultimate verified event when every interior row verifies, or the first
/// broken interior row's recovery metadata.
///
/// # Errors
/// Returns an error only if the file cannot be opened or read.
fn verify_interior_chain(path: &Path) -> KResult<InteriorChainVerification> {
    if !path.exists() {
        return Ok(InteriorChainVerification {
            previous_event: None,
            failure: None,
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
                            return Ok(InteriorChainVerification {
                                previous_event: None,
                                failure: Some(InteriorChainFailure {
                                    reason: SealReason::HashMismatch,
                                    claimed_last_id: Some(event.id),
                                    failure_offset: pending_offset,
                                }),
                            });
                        }
                    }
                    RowCheck::HashMismatch(event) => {
                        return Ok(InteriorChainVerification {
                            previous_event: None,
                            failure: Some(InteriorChainFailure {
                                reason: SealReason::HashMismatch,
                                claimed_last_id: Some(event.id),
                                failure_offset: pending_offset,
                            }),
                        });
                    }
                    RowCheck::Unparseable => {
                        return Ok(InteriorChainVerification {
                            previous_event: None,
                            failure: Some(InteriorChainFailure {
                                reason: SealReason::Unparseable,
                                claimed_last_id: prev.as_ref().map(|p| p.id),
                                failure_offset: pending_offset,
                            }),
                        });
                    }
                }
            }
        }
        pending = Some((line, line_offset));
    }

    Ok(InteriorChainVerification {
        previous_event: prev,
        failure: None,
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
fn recover_and_open(path: &Path) -> KResult<(std::fs::File, i64, [u8; 32])> {
    let verification = verify_interior_chain(path)?;
    let (next_id, prev_hash) = if let Some(failure) = verification.failure {
        seal_and_roll(
            path,
            failure.reason,
            failure.claimed_last_id,
            failure.failure_offset,
        )?
    } else {
        let previous_event = verification.previous_event;
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
                        hex::encode(&prev_hash[..8]) /* first 8 bytes (16 hex chars) sufficient for diagnostics */
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
    };

    let file = open_append(path).map_err(|e| {
        KmsError::ServerError(format!(
            "audit: cannot open log file {}: {e}",
            path.display()
        ))
    })?;

    Ok((file, next_id, prev_hash))
}
