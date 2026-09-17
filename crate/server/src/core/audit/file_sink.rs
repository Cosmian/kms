//! Tamper-evident JSONL audit sink with recovery and an exclusive cross-instance lock.
//!
//! Recovery runs in the writer task, allowing server startup to continue independently.

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

const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

const OPEN_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Cross-task state for the optional `max_size_bytes` write-stop cap.
///
/// The writer sets `size_limit_reached`; producers read it before enqueueing.
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

/// Writes and synchronises one JSONL event during recovery.
fn write_event_line(file: &mut std::fs::File, event: &AuditEvent) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(b"\n")?;
    file.sync_data()
}

/// Writes a recovery sentinel, advancing the chain only after a successful sync.
/// This synchronous path runs before the sink is resumed.
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

/// File-backed [`AuditSink`] for a tamper-evident JSONL chain.
///
/// A failed write may leave a partial row. The next write truncates back to
/// `committed_len` before appending.
pub(crate) struct FileSink {
    path: PathBuf,
    write_state: Arc<AuditWriteState>,
    /// Set by [`Self::resume`].
    file: Option<std::fs::File>,
    /// End of the last durably written row.
    committed_len: u64,
    /// Whether bytes past `committed_len` must be discarded.
    needs_repair: bool,
    /// Kept alive because dropping the handle releases the OS lock; never read again.
    _lock: Option<std::fs::File>,
}

impl FileSink {
    /// Builds a file sink that has not yet been resumed.
    pub(super) const fn new(path: PathBuf, write_state: Arc<AuditWriteState>) -> Self {
        Self {
            path,
            write_state,
            file: None,
            committed_len: 0,
            needs_repair: false,
            _lock: None,
        }
    }

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

    /// Waits for the exclusive lock, then recovers and opens the audit file. Every fault
    /// — lock contention, recovery/open, and stat — retries in place, so this never
    /// returns `Err` in practice.
    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        let lock_path = lock_file_path(&self.path);
        let mut lock_contended_logged = false;
        let lock = loop {
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
        self._lock = Some(lock);

        let (file, next_id, prev_hash) = loop {
            // Recovery scans the file and may rename it, so keep it off the async worker.
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

        self.committed_len = loop {
            match file.metadata() {
                Ok(meta) => break meta.len(),
                Err(e) => {
                    error!(
                        "AuditFileStore: cannot stat recovered log file {} ({e}) — retrying",
                        self.path.display()
                    );
                    tokio::time::sleep(OPEN_RETRY_INTERVAL).await;
                }
            }
        };
        enforce_size_cap(self.committed_len, &self.write_state, &self.path);
        self.file = Some(file);
        Ok(ChainHead { next_id, prev_hash })
    }

    /// Serialises and synchronises one event, repairing any previous partial write first.
    ///
    /// # Errors
    /// Returns an error if the sink is not resumed or file I/O fails.
    async fn write_event_atomic(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        let mut row = serde_json::to_vec(event)
            .map_err(|e| InterfaceError::Default(format!("audit: cannot serialise event: {e}")))?;
        row.push(b'\n');

        self.repair_if_needed().map_err(|e| InterfaceError::Io {
            context: "audit: torn-tail repair failed".to_owned(),
            source: e,
        })?;

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
                Err(InterfaceError::Io {
                    context: "audit: write failed".to_owned(),
                    source: e,
                })
            }
        }
    }

    fn is_write_capacity_exceeded(&self) -> bool {
        self.write_state.size_limit_reached.load(Ordering::Relaxed)
    }

    async fn final_sync(&mut self) -> InterfaceResult<()> {
        self.repair_if_needed().map_err(|e| InterfaceError::Io {
            context: "audit: final sync repair failed".to_owned(),
            source: e,
        })?;
        if let Some(file) = self.file.as_mut() {
            file.sync_data().map_err(|e| InterfaceError::Io {
                context: "audit: final sync failed".to_owned(),
                source: e,
            })?;
        }
        Ok(())
    }
}

/// Marks the sink capped once its committed length reaches the configured limit.
/// The write crossing the limit remains committed.
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

pub(super) fn lock_file_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(OsString::new, OsStr::to_os_string);
    name.push(".lock");
    path.with_file_name(name)
}

/// Attempts to acquire the advisory lock without blocking.
/// Dropping the returned file releases the lock.
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

    fn make_sink(file: std::fs::File, committed_len: u64) -> FileSink {
        FileSink {
            path: PathBuf::new(),
            write_state: Arc::new(AuditWriteState::default()),
            file: Some(file),
            committed_len,
            needs_repair: false,
            _lock: None,
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
