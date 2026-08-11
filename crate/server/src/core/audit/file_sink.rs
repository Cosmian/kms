//! `FileSink`: the tamper-evident JSONL file audit backend.
//!
//! Hash chain
//! ==========
//! Each persisted row carries:
//!   `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
//!   `row_hash`  — SHA-256 of this row's canonical bytes (including `prev_hash`)
//!
//! Use `ckms audit verify --path <file>` to validate the chain offline.

use std::{
    io::{BufRead, BufReader, Seek, Write},
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use cosmian_kms_access::audit::{AuditEvent, verify_event};
use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};

use crate::{error::KmsError, result::KResult};

/// Bytes read from the end of an existing log to locate the last complete event
/// at startup.  64 KiB comfortably covers many events; a single serialised
/// `AuditEvent` is typically <2 KiB.
const TAIL_WINDOW: u64 = 65_536;

/// The JSONL file audit backend. Holds the append-mode write handle; `resume()` opens a
/// second, independent read handle on the same path to locate the chain tail.
pub(super) struct FileSink {
    path: PathBuf,
    file: std::fs::File,
}

impl FileSink {
    /// Opens `path` for appending, creating parent directories as needed.
    ///
    /// Opening eagerly (rather than lazily on the first write) means an unwritable path aborts
    /// server startup immediately instead of silently disabling audit logging at runtime.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened.
    pub(super) fn open(path: &Path) -> KResult<Self> {
        let file = open_append(path).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot open log file {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }
}

#[async_trait]
impl AuditSink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    async fn resume(&mut self) -> InterfaceResult<ChainHead> {
        if !self.path.exists() {
            return Ok(ChainHead::EMPTY);
        }

        let mut file = std::fs::File::open(&self.path).map_err(|e| {
            InterfaceError::Db(format!(
                "audit: cannot open existing log file {}: {e}",
                self.path.display()
            ))
        })?;

        let file_len = file
            .metadata()
            .map_err(|e| InterfaceError::Db(format!("audit: cannot stat log file: {e}")))?
            .len();
        if file_len == 0 {
            return Ok(ChainHead::EMPTY);
        }

        // Seek to the tail window so startup cost is O(1) regardless of log size.
        let seek_pos = file_len.saturating_sub(TAIL_WINDOW);
        if seek_pos > 0 {
            file.seek(std::io::SeekFrom::Start(seek_pos))
                .map_err(|e| InterfaceError::Db(format!("audit: cannot seek log file: {e}")))?;
        }

        let reader = BufReader::new(file);
        let mut last_line = String::new();
        // When seek_pos > 0 the first buffered read may start mid-line (a partial fragment cut
        // by the seek); taking the LAST non-empty line is correct regardless because subsequent
        // lines are complete.
        for line in reader.lines() {
            let line = line
                .map_err(|e| InterfaceError::Db(format!("audit: error reading log file: {e}")))?;
            if !line.trim().is_empty() {
                last_line = line;
            }
        }

        if last_line.is_empty() {
            return Ok(ChainHead::EMPTY);
        }

        let last_event: AuditEvent = serde_json::from_str(&last_line).map_err(|e| {
            InterfaceError::Db(format!(
                "audit: cannot parse last line of log file: {e}\nLine: {last_line}"
            ))
        })?;

        // Verify the hash of the last persisted event before trusting it as the chain seed.
        // A mismatch signals tampering or a crash-truncated write.
        if !verify_event(&last_event) {
            return Err(InterfaceError::Db(format!(
                "audit: last persisted event (id={}) has an invalid row_hash — the log tail \
                 may be corrupted or tampered. Remove or repair the last line before restarting.",
                last_event.id
            )));
        }

        Ok(ChainHead {
            next_id: last_event.id + 1,
            prev_hash: last_event.row_hash,
        })
    }

    /// Serialises `event` as a single JSONL line and syncs to storage.
    ///
    /// `sync_data()` is called on every write to guarantee durability: without it data sits in
    /// the kernel page cache and is lost on a power failure. The tradeoff is one `fsync` per
    /// audit event; high-throughput deployments can reduce cost by batching syncs.
    async fn write_event(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
        serde_json::to_writer(&mut self.file, event)
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        self.file
            .write_all(b"\n")
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        self.file
            .sync_data()
            .map_err(|e| InterfaceError::Db(e.to_string()))
    }

    /// A full disk keeps the historical behaviour: log, reuse the chain slot, and keep serving.
    /// Losing a database is unrecoverable (see `PgAuditSink`); losing a local file is not treated
    /// the same way here, matching the original file-only implementation's tradeoff.
    fn write_failure_is_fatal(&self) -> bool {
        false
    }

    async fn final_sync(&mut self) -> InterfaceResult<()> {
        self.file
            .sync_data()
            .map_err(|e| InterfaceError::Db(e.to_string()))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Write as _;

    use cosmian_kms_access::audit::{AuditEvent, AuditResult, compute_row_hash};
    use cosmian_kms_interfaces::AuditSink;
    use time::OffsetDateTime;

    use super::FileSink;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kms_audit_filesink_test_{}_{label}.jsonl",
            std::process::id()
        ))
    }

    fn make_event(id: i64, prev_hash: [u8; 32]) -> AuditEvent {
        let mut ev = AuditEvent {
            id,
            timestamp: OffsetDateTime::now_utc(),
            operation: "Encrypt".to_owned(),
            user: "alice".to_owned(),
            object_uid: Some("obj-1".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: None,
            prev_hash,
            row_hash: [0_u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    #[tokio::test]
    async fn resume_of_missing_file_is_empty_chain_head() {
        let path = temp_path("missing");
        std::fs::remove_file(&path).ok();
        let mut sink = FileSink::open(&path).unwrap();
        let head = sink.resume().await.unwrap();
        assert_eq!(head.next_id, 0);
        assert_eq!(head.prev_hash, [0_u8; 32]);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn write_then_resume_round_trip() {
        let path = temp_path("round_trip");
        std::fs::remove_file(&path).ok();
        {
            let mut sink = FileSink::open(&path).unwrap();
            let ev0 = make_event(0, [0_u8; 32]);
            sink.write_event(&ev0).await.unwrap();
            let ev1 = make_event(1, ev0.row_hash);
            sink.write_event(&ev1).await.unwrap();
        }
        let mut sink = FileSink::open(&path).unwrap();
        let head = sink.resume().await.unwrap();
        assert_eq!(head.next_id, 2);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn resume_rejects_tampered_last_line() {
        let path = temp_path("tampered");
        std::fs::remove_file(&path).ok();
        {
            let mut sink = FileSink::open(&path).unwrap();
            let ev0 = make_event(0, [0_u8; 32]);
            sink.write_event(&ev0).await.unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let mut ev: AuditEvent = serde_json::from_str(content.trim()).unwrap();
        ev.row_hash = [0_u8; 32];
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&ev).unwrap())).unwrap();

        let mut sink = FileSink::open(&path).unwrap();
        let result = sink.resume().await;
        assert!(
            result.is_err(),
            "resume() must reject a tampered last event"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn open_fails_when_path_is_unopenable() {
        let blocker = temp_path("unopenable_blocker");
        std::fs::remove_file(&blocker).ok();
        std::fs::write(&blocker, b"i am a file, not a directory").unwrap();
        let bogus_path = blocker.join("audit.jsonl");

        let result = FileSink::open(&bogus_path);
        assert!(
            result.is_err(),
            "open() must fail when the parent is not a directory"
        );
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("cannot open"),
            "unexpected error message: {err}"
        );

        std::fs::remove_file(&blocker).ok();
    }

    #[tokio::test]
    async fn malformed_last_line_makes_resume_fail() {
        let path = temp_path("malformed");
        std::fs::remove_file(&path).ok();
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{{not valid json at all").unwrap();
        drop(file);

        let mut sink = FileSink::open(&path).unwrap();
        let result = sink.resume().await;
        assert!(
            result.is_err(),
            "resume() must reject a malformed last line"
        );
        std::fs::remove_file(&path).ok();
    }
}
