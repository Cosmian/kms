//! Tamper-evident JSONL file persistence for the audit log: the always-start recovery
//! loop, the exclusive cross-instance lock, and `FileSink`'s implementation of
//! `cosmian_kms_interfaces::AuditSink`.
//!
//! Always-start recovery
//! ======================
//! [`FileSink::resume`] guarantees the KMS always starts regardless of the audit log's
//! state: it acquires the exclusive lock and recovers/opens the file (see the
//! `recovery` module for tail classification and seal-and-roll) inside a self-healing
//! retry loop that never returns an error — the generic writer task simply awaits it
//! while events are buffered upstream in the channel, never blocking the caller.

use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};

use async_trait::async_trait;
use cosmian_kms_access::audit::{AuditEvent, AuditEventDraft};
use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
use cosmian_logger::{debug, error};

use super::recovery::recover_and_open;

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

/// Serialises `event` as a single JSONL line and durably syncs it to `file`.
///
/// Used by [`write_recovery_sentinel`] (recovery-time, called from a `spawn_blocking`
/// context with no async runtime available). The steady-state path
/// ([`FileSink::write_event_atomic`]) has its own buffered variant so it can track
/// `committed_len` without an extra `stat` per event — see its doc comment.
///
/// `sync_data()` is called on every write to guarantee durability: without it data sits
/// in the kernel page cache and is lost on a power failure.
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
pub(super) fn write_recovery_sentinel(
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
/// with the always-start, self-healing recovery documented at the top of this module. A
/// write failure is always logged and the event skipped — never fatal to the server,
/// preserving the file backend's historical behaviour.
///
/// A write can fail after some of its bytes already hit the OS (a short write, or an
/// error between the JSON and its trailing newline): the row is not committed, but the
/// bytes are already durable. [`Self::write_event_atomic`] truncates back to
/// `committed_len` before its next attempt, closing that gap the same way
/// `classify_tail`'s `TruncateContinue` does at boot — just triggered by the next write
/// instead of the next restart.
pub(crate) struct FileSink {
    path: PathBuf,
    write_state: Arc<AuditWriteState>,
    /// `None` until [`Self::resume`] has run; the trait contract guarantees `resume` is
    /// called exactly once before any `write_event_atomic`.
    file: Option<std::fs::File>,
    /// End of the last durably written, complete row. Set once by `resume()`, from the
    /// recovered file's length; advanced by every successful write.
    committed_len: u64,
    /// A previous write left bytes past `committed_len` that must be discarded before
    /// the next append.
    needs_repair: bool,
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
            committed_len: 0,
            needs_repair: false,
            lock: None,
        }
    }

    /// Discards any bytes past `committed_len` left by a previous failed write.
    fn repair_if_needed(&mut self) -> std::io::Result<()> {
        if !self.needs_repair {
            return Ok(());
        }
        if let Some(file) = self.file.as_mut() {
            file.set_len(self.committed_len)?;
            file.sync_data()?;
        }
        self.needs_repair = false;
        Ok(())
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
    /// retries indefinitely instead of ever reporting one — except if the recovered file
    /// cannot even be `stat`'d, an anomaly no retry loop here is positioned to fix.
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

        self.committed_len = file
            .metadata()
            .map_err(|e| {
                InterfaceError::Default(format!("audit: cannot stat recovered log file: {e}"))
            })?
            .len();
        enforce_size_cap(self.committed_len, &self.write_state, &self.path);
        self.file = Some(file);
        Ok(ChainHead { next_id, prev_hash })
    }

    /// Serialises `event` as a single JSONL line, repairing any torn tail from a
    /// previous failed write first so a partial row is never observable mid-session.
    ///
    /// Serializes to a buffer before touching the file — a serialization failure must
    /// never touch it — and tracks the exact byte length written in `committed_len`
    /// instead of a `stat` per event.
    ///
    /// # Errors
    /// Returns an error if the sink has not been `resume()`d yet, or if the underlying
    /// write/sync fails. Neither ever advances the chain — see the trait contract.
    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        let mut row = serde_json::to_vec(event)
            .map_err(|e| InterfaceError::Default(format!("audit: cannot serialise event: {e}")))?;
        row.push(b'\n');

        self.repair_if_needed()
            .map_err(|e| InterfaceError::Default(format!("audit: torn-tail repair failed: {e}")))?;

        let file = self.file.as_mut().ok_or_else(|| {
            InterfaceError::Default(
                "audit: FileSink::write_event_atomic called before resume()".to_owned(),
            )
        })?;
        match file.write_all(&row).and_then(|()| file.sync_data()) {
            Ok(()) => {
                self.committed_len += u64::try_from(row.len()).unwrap_or(u64::MAX);
                enforce_size_cap(self.committed_len, &self.write_state, &self.path);
                Ok(())
            }
            Err(e) => {
                self.needs_repair = true;
                Err(InterfaceError::Default(format!("audit: write failed: {e}")))
            }
        }
    }

    fn is_write_capacity_exceeded(&self) -> bool {
        self.write_state.size_limit_reached.load(Ordering::Relaxed)
    }

    /// Repairs a torn tail before the final sync so a clean shutdown never leaves one
    /// for the next boot to find.
    async fn final_sync(&mut self) -> InterfaceResult<()> {
        self.repair_if_needed().map_err(|e| {
            InterfaceError::Default(format!("audit: final sync repair failed: {e}"))
        })?;
        if let Some(file) = self.file.as_mut() {
            file.sync_data()
                .map_err(|e| InterfaceError::Default(format!("audit: final sync failed: {e}")))?;
        }
        Ok(())
    }
}

/// Checks `len` (the sink's current committed length) against `write_state.max_size_bytes`
/// and updates `write_state` on the first transition into the capped state (logging
/// once). Called right after the sink resumes (an already-oversized log must block
/// immediately) and again after every successful write (a write that crosses the cap is
/// allowed to land, then blocks everything after it).
fn enforce_size_cap(len: u64, write_state: &AuditWriteState, path: &Path) {
    let Some(cap) = write_state.max_size_bytes else {
        return;
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

    /// Builds a `FileSink` already past `resume()`, bypassing the real lock+recovery
    /// dance so the write path can be tested in isolation.
    fn make_sink(file: std::fs::File, committed_len: u64) -> FileSink {
        FileSink {
            path: PathBuf::new(),
            write_state: Arc::new(AuditWriteState::default()),
            file: Some(file),
            committed_len,
            needs_repair: false,
            lock: None,
        }
    }

    #[tokio::test]
    async fn write_event_appends_valid_row_and_updates_committed_len() {
        let path = temp_path("basic");
        std::fs::remove_file(&path).ok();
        let mut sink = make_sink(open_for_append(&path), 0);

        sink.write_event_atomic(&sample_event(0, [0_u8; 32]))
            .await
            .expect("write");

        let rows = read_rows(&path);
        assert_eq!(rows.len(), 1);
        assert!(verify_event(&rows[0]));
        assert_eq!(
            sink.committed_len,
            std::fs::metadata(&path).expect("metadata").len()
        );
    }

    /// A write that fails mid-run (here, a read-only handle) must not corrupt the
    /// chain — the next successful write (reusing the same slot, as
    /// `write_draft_to_chain` does) must leave exactly one valid row, not a
    /// concatenation with whatever the failed attempt left behind.
    #[cfg(not(target_os = "windows"))] // Fails on Windows, probably for reasons related to file handles (passes reliably on Linux/macOS).
    #[tokio::test]
    async fn write_failure_sets_needs_repair_and_is_healed_by_next_success() {
        let path = temp_path("heal");
        std::fs::remove_file(&path).ok();
        std::fs::File::create(&path).expect("create");
        let read_only = std::fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open read-only");
        let mut sink = make_sink(read_only, 0);

        let event = sample_event(0, [0_u8; 32]);
        assert!(sink.write_event_atomic(&event).await.is_err());
        assert!(sink.needs_repair);

        // The underlying handle becomes writable again — mirrors the process
        // continuing to run and retrying the same slot.
        sink.file = Some(open_for_append(&path));
        sink.write_event_atomic(&event)
            .await
            .expect("retry succeeds");
        assert!(!sink.needs_repair);

        let rows = read_rows(&path);
        assert_eq!(rows.len(), 1, "no leftover garbage from the failed attempt");
        assert!(verify_event(&rows[0]));
    }

    #[cfg(not(target_os = "windows"))] // Fails on Windows, probably for reasons related to file handles (passes reliably on Linux/macOS).
    #[tokio::test]
    async fn final_sync_repairs_pending_tail_without_writing_a_new_row() {
        let path = temp_path("final_sync");
        std::fs::remove_file(&path).ok();
        let mut sink = make_sink(open_for_append(&path), 0);
        sink.file
            .as_mut()
            .expect("file")
            .write_all(b"torn-garbage-without-newline")
            .expect("write garbage");
        sink.needs_repair = true;

        sink.final_sync().await.expect("final_sync");

        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 0);
        assert!(!sink.needs_repair);
    }

    #[tokio::test]
    async fn committed_len_is_isolated_from_writes_behind_the_sinks_back() {
        let path = temp_path("committed_view");
        std::fs::remove_file(&path).ok();
        let mut sink = make_sink(open_for_append(&path), 0);
        sink.write_event_atomic(&sample_event(0, [0_u8; 32]))
            .await
            .expect("write");
        let committed = sink.committed_len;

        // Bytes land on disk without going through the sink (e.g. a future write
        // not yet reflected in `committed_len`).
        open_for_append(&path)
            .write_all(b"unrelated-bytes")
            .expect("write unrelated bytes");

        assert_eq!(sink.committed_len, committed);
        assert_ne!(std::fs::metadata(&path).expect("metadata").len(), committed);
    }
}
