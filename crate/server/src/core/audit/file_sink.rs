//! Tamper-evident JSONL file persistence for the audit log: writer lifecycle, the
//! exclusive cross-instance lock, and the `AuditSink` write abstraction.
//!
//! Always-start recovery
//! ======================
//! `writer_supervisor` guarantees the KMS always starts regardless of the audit log's
//! state: it acquires the exclusive lock and recovers/opens the file (see the
//! `recovery` module for tail classification and seal-and-roll) inside a self-healing
//! retry loop that runs in the background, never blocking the caller.

use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
};

use cosmian_kms_access::audit::AuditEvent;
use cosmian_logger::{debug, error};
use tokio::sync::mpsc;

use super::{recovery::recover_and_open, store::WriterMsg, writer::writer_loop};

/// How long to wait between attempts to acquire the exclusive audit-log lock while a
/// peer instance (e.g. the other side of a rolling update on a shared volume) holds it.
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// How long to wait between attempts to recover/open the audit log after a
/// content-independent I/O fault (EACCES, EIO, read-only mount, missing disk).
const OPEN_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Minimum interval between "still capped" debug log lines while blocked events
/// keep arriving — avoids flooding the log once `max_size_bytes` is reached.
pub(super) const CAPPED_DEBUG_LOG_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(500);

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

/// Abstraction over the audit log's underlying writer.
///
/// This exists so the fault path (`write_event` failing mid-run) can be
/// exercised in tests with a mock sink, without touching real files —
/// production always uses `FileSink`.
pub(super) trait AuditSink {
    /// Serialises and durably persists one event.
    ///
    /// # Errors
    /// On failure, the caller must NOT consider the event committed: the writer does
    /// not advance `next_id`/`prev_hash`, and the sink guarantees the partially written
    /// bytes are never observable as a chain row — either because the write is atomic,
    /// or because the sink discards them before its next successful write.
    fn write_event(&mut self, event: &AuditEvent) -> std::io::Result<()>;

    /// Called once when the writer loop exits (channel closed). Default is a
    /// no-op.
    fn final_sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Current on-disk length in bytes, used to enforce `max_size_bytes`.
    ///
    /// Only the real `std::fs::File` sink can answer this meaningfully; mock sinks
    /// used for fault-injection tests never configure a size cap, so the default
    /// (`Ok(0)`) is never exercised by them.
    fn current_len(&self) -> std::io::Result<u64> {
        Ok(0)
    }
}

/// A file-backed sink that lazily repairs a torn tail left by a previous failed
/// write, instead of waiting for the next process restart to discover it.
///
/// A write can fail after some of its bytes already hit the OS (a short write, or an
/// error between the JSON and its trailing newline): the row is not committed, but the
/// bytes are already durable. Truncating back to `committed_len` closes that gap the
/// same way `classify_tail`'s `TruncateContinue` does at boot — just triggered by the
/// next write instead of the next restart.
pub(super) struct FileSink {
    file: std::fs::File,
    /// End of the last durably written, complete row.
    committed_len: u64,
    /// A previous write left bytes past `committed_len` that must be discarded before
    /// the next append.
    needs_repair: bool,
}

impl FileSink {
    /// `committed_len` must be `file`'s length at the time of opening — every byte up
    /// to it is a durable, complete row (guaranteed by `recovery::recover_and_open`).
    pub(super) const fn new(file: std::fs::File, committed_len: u64) -> Self {
        Self {
            file,
            committed_len,
            needs_repair: false,
        }
    }

    fn repair_if_needed(&mut self) -> std::io::Result<()> {
        if !self.needs_repair {
            return Ok(());
        }
        self.file.set_len(self.committed_len)?;
        self.file.sync_data()?;
        self.needs_repair = false;
        Ok(())
    }
}

impl AuditSink for FileSink {
    /// Serialises `event` as a single JSONL line, repairing any torn tail from a
    /// previous failed write first so a partial row is never observable mid-session.
    ///
    /// `sync_data()` is called on every write to guarantee durability: without it
    /// data sits in the kernel page cache and is lost on a power failure.  The
    /// tradeoff is one `fsync` per audit event; high-throughput deployments can
    /// reduce cost by batching syncs (every N events or every T ms).
    fn write_event(&mut self, event: &AuditEvent) -> std::io::Result<()> {
        // Serialize first: a serialization failure must never touch the file.
        let mut row = serde_json::to_vec(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        row.push(b'\n');

        self.repair_if_needed()?;

        match self
            .file
            .write_all(&row)
            .and_then(|()| self.file.sync_data())
        {
            Ok(()) => {
                self.committed_len += u64::try_from(row.len()).unwrap_or(u64::MAX);
                Ok(())
            }
            Err(e) => {
                self.needs_repair = true;
                Err(e)
            }
        }
    }

    /// Repairs a torn tail before the final sync so a clean shutdown never leaves one
    /// for the next boot to find.
    fn final_sync(&mut self) -> std::io::Result<()> {
        self.repair_if_needed()?;
        self.file.sync_data()
    }

    fn current_len(&self) -> std::io::Result<u64> {
        Ok(self.committed_len)
    }
}

/// Checks `sink`'s current on-disk length against `write_state.max_size_bytes` and
/// updates `write_state` on the first transition into the capped state (logging
/// once). Called right after the writer opens/recovers the file (an already-
/// oversized log must block immediately) and again after every successful write
/// (a write that crosses the cap is allowed to land, then blocks everything after
/// it).
pub(super) fn enforce_size_cap<S: AuditSink>(sink: &S, write_state: &AuditWriteState, path: &Path) {
    let Some(cap) = write_state.max_size_bytes else {
        return;
    };
    let len = match sink.current_len() {
        Ok(len) => len,
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
    let was_already_capped = write_state
        .size_limit_reached
        .swap(true, std::sync::atomic::Ordering::Relaxed);
    if !was_already_capped {
        error!(
            "AuditFileStore: audit log {} reached its configured max_size_bytes cap \
             ({len} bytes >= {cap}) — audit writing is blocked until the log is safely \
             remediated and the KMS is restarted",
            path.display()
        );
    }
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
pub(super) async fn writer_supervisor(
    path: PathBuf,
    rx: mpsc::Receiver<WriterMsg>,
    dropped_count: Arc<AtomicU64>,
    write_state: Arc<AuditWriteState>,
) {
    let lock_path = lock_file_path(&path);
    let mut lock_contended_logged = false;
    let _lock = loop {
        match try_acquire_lock(&lock_path) {
            Ok(lock) => break lock,
            // `try_acquire_lock` also fails for reasons unrelated to contention (EACCES,
            // EROFS, directory-creation failure) — only `WouldBlock` means a peer holds
            // the lock; anything else is a deployment fault and must be logged as such,
            // not masked as the (benign, expected-in-HA) "held by another instance" case.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
            Err(e) => {
                error!(
                    "AuditFileStore: cannot acquire audit log lock {} ({e}) — retrying",
                    lock_path.display()
                );
                tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
            }
        }
    };

    let (sink, next_id, prev_hash) = loop {
        // `recover_and_open` does blocking `std::fs` I/O (whole-file scan, hash, and
        // possible rename on seal-and-roll) — run it on the blocking pool so a large
        // audit log doesn't monopolize this tokio worker thread during startup/recovery.
        let path_for_recovery = path.clone();
        let recovered =
            tokio::task::spawn_blocking(move || recover_and_open(&path_for_recovery)).await;
        match recovered {
            Ok(Ok(triple)) => break triple,
            Ok(Err(e)) => {
                error!(
                    "AuditFileStore: cannot open audit log {} ({e}) — retrying",
                    path.display()
                );
                tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
            }
            Err(join_err) => {
                error!("AuditFileStore: recovery task failed to run ({join_err}) — retrying");
                tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
            }
        }
    };

    writer_loop(
        sink,
        next_id,
        prev_hash,
        rx,
        dropped_count,
        write_state,
        &path,
    )
    .await;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::io::Read;

    use cosmian_kms_access::audit::{AuditResult, compute_row_hash, verify_event};
    use time::OffsetDateTime;

    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kms_file_sink_test_{}_{label}.jsonl",
            std::process::id()
        ))
    }

    fn sample_event(id: i64, prev_hash: [u8; 32]) -> AuditEvent {
        let mut ev = AuditEvent {
            id,
            timestamp: OffsetDateTime::now_utc(),
            operation: "Encrypt".to_owned(),
            user: "alice".to_owned(),
            object_uid: Some("obj-1".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 1,
            request_id: None,
            details: None,
            prev_hash,
            row_hash: [0_u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    fn read_rows(path: &Path) -> Vec<AuditEvent> {
        let mut content = String::new();
        std::fs::File::open(path)
            .expect("open")
            .read_to_string(&mut content)
            .expect("read");
        content
            .lines()
            .map(|l| serde_json::from_str(l).expect("valid AuditEvent JSON"))
            .collect()
    }

    fn open_for_append(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open for append")
    }

    #[test]
    fn write_event_appends_valid_row_and_updates_committed_len() {
        let path = temp_path("basic");
        std::fs::remove_file(&path).ok();
        let mut sink = FileSink::new(open_for_append(&path), 0);

        sink.write_event(&sample_event(0, [0_u8; 32]))
            .expect("write");

        let rows = read_rows(&path);
        assert_eq!(rows.len(), 1);
        assert!(verify_event(&rows[0]));
        assert_eq!(
            sink.current_len().expect("current_len"),
            std::fs::metadata(&path).expect("metadata").len()
        );
    }

    /// A write that fails mid-run (here, a read-only handle) must not corrupt the
    /// chain — the next successful write (reusing the same slot, as
    /// `write_draft_to_chain` does) must leave exactly one valid row, not a
    /// concatenation with whatever the failed attempt left behind.
    #[test]
    fn write_failure_sets_needs_repair_and_is_healed_by_next_success() {
        let path = temp_path("heal");
        std::fs::remove_file(&path).ok();
        std::fs::File::create(&path).expect("create");
        let read_only = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open read-only");
        let mut sink = FileSink::new(read_only, 0);

        let event = sample_event(0, [0_u8; 32]);
        assert!(sink.write_event(&event).is_err());
        assert!(sink.needs_repair);

        // The underlying handle becomes writable again — mirrors the process
        // continuing to run and retrying the same slot.
        sink.file = open_for_append(&path);
        sink.write_event(&event).expect("retry succeeds");
        assert!(!sink.needs_repair);

        let rows = read_rows(&path);
        assert_eq!(rows.len(), 1, "no leftover garbage from the failed attempt");
        assert!(verify_event(&rows[0]));
    }

    #[test]
    fn final_sync_repairs_pending_tail_without_writing_a_new_row() {
        let path = temp_path("final_sync");
        std::fs::remove_file(&path).ok();
        let mut sink = FileSink::new(open_for_append(&path), 0);
        sink.file
            .write_all(b"torn-garbage-without-newline")
            .expect("write garbage");
        sink.needs_repair = true;

        sink.final_sync().expect("final_sync");

        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 0);
        assert!(!sink.needs_repair);
    }

    #[test]
    fn current_len_reports_committed_view_not_raw_file_length() {
        let path = temp_path("committed_view");
        std::fs::remove_file(&path).ok();
        let mut sink = FileSink::new(open_for_append(&path), 0);
        sink.write_event(&sample_event(0, [0_u8; 32]))
            .expect("write");
        let committed = sink.current_len().expect("current_len");

        // Bytes land on disk without going through the sink (e.g. a future write
        // not yet reflected in `committed_len`).
        open_for_append(&path)
            .write_all(b"unrelated-bytes")
            .expect("write unrelated bytes");

        assert_eq!(sink.current_len().expect("current_len"), committed);
        assert_ne!(std::fs::metadata(&path).expect("metadata").len(), committed);
    }
}
