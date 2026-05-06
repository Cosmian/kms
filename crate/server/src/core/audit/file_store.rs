//! Tamper-evident JSONL file backend for audit events.
//!
//! Architecture
//! ============
//! * `AuditFileStore` is a cheaply cloneable handle (wraps a channel `Sender`).
//! * A single background tokio task (`writer_loop`) is the **sole owner** of the
//!   audit file, the monotonic event counter, and the previous-row hash.  This
//!   design avoids any mutex around the file and guarantees write order under
//!   concurrent requests.
//! * The middleware calls `enqueue()` which is a non-blocking `try_send`.  If the
//!   channel is full (> 1024 buffered events) the draft is silently dropped and a
//!   warning is logged — we never block the request path.
//!
//! Hash chain
//! ==========
//! Each persisted row carries:
//!   `prev_hash` — SHA-256 of the previous row's canonical bytes (all-zeros for row 0)
//!   `row_hash`  — SHA-256 of this row's canonical bytes (including `prev_hash`)
//!
//! Use `ckms audit verify --path <file>` to validate the chain offline.

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::Arc,
};

use cosmian_kms_access::audit::{AuditEventDraft, AuditEventFull, AuditResult, compute_row_hash};
use cosmian_logger::{debug, warn};
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::{error::KmsError, result::KResult};

/// Channel capacity.  Events beyond this limit are dropped (non-blocking path).
const CHANNEL_CAPACITY: usize = 1024;

/// A cheaply cloneable handle to the audit writer task.
///
/// Cloning this value is O(1) — it only increments the `Arc` ref-count on the
/// sender.  All clones share the same underlying channel and therefore the same
/// writer task.
#[derive(Clone)]
pub(crate) struct AuditFileStore {
    sender: Arc<mpsc::Sender<AuditEventDraft>>,
}

impl AuditFileStore {
    /// Initialises the audit file store and spawns the background writer task.
    ///
    /// If `path` already contains events the writer task will continue the
    /// existing chain; the next event ID will be `last_id + 1` and `prev_hash`
    /// will be taken from the last persisted row.
    ///
    /// # Errors
    /// Returns an error if the audit file cannot be opened or if an existing
    /// file contains a malformed last line.
    pub(crate) fn start(path: PathBuf) -> KResult<Self> {
        // ── Read the tail of an existing log to resume the chain ─────────
        let (next_id, prev_hash) = Self::resume_chain(&path)?;
        debug!(
            "AuditFileStore: resuming at id={next_id}, prev_hash={}",
            hex::encode(prev_hash)
        );

        let (tx, rx) = mpsc::channel::<AuditEventDraft>(CHANNEL_CAPACITY);

        // Spawn the sole writer task
        tokio::spawn(async move {
            writer_loop(path, next_id, prev_hash, rx).await;
        });

        Ok(Self {
            sender: Arc::new(tx),
        })
    }

    /// Enqueues a draft event for writing.  Non-blocking: if the channel is
    /// full the event is silently dropped after logging a warning.
    pub(crate) fn enqueue(&self, draft: AuditEventDraft) {
        match self.sender.try_send(draft) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("AuditFileStore: channel full, dropping audit event");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("AuditFileStore: writer task has stopped, audit event dropped");
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Reads the last line of `path` (if any) to extract the last `id` and
    /// `row_hash` so the chain can be continued on restart.
    fn resume_chain(path: &PathBuf) -> KResult<(i64, [u8; 32])> {
        if !path.exists() {
            return Ok((0, [0_u8; 32]));
        }

        let file = std::fs::File::open(path).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot open existing log file {}: {e}",
                path.display()
            ))
        })?;

        let reader = BufReader::new(file);
        let mut last_line = String::new();

        for line in reader.lines() {
            let line = line.map_err(|e| {
                KmsError::ServerError(format!("audit: error reading log file: {e}"))
            })?;
            if !line.trim().is_empty() {
                last_line = line;
            }
        }

        if last_line.is_empty() {
            return Ok((0, [0_u8; 32]));
        }

        let last_event: AuditEventFull = serde_json::from_str(&last_line).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot parse last line of log file: {e}\nLine: {last_line}"
            ))
        })?;

        Ok((last_event.id + 1, last_event.row_hash))
    }
}

/// The background writer task.  Sole owner of the open file, the id counter,
/// and `prev_hash`.  Never panics — errors are logged and the loop continues.
async fn writer_loop(
    path: PathBuf,
    mut next_id: i64,
    mut prev_hash: [u8; 32],
    mut rx: mpsc::Receiver<AuditEventDraft>,
) {
    // Open the file in append mode, creating it if needed.
    let mut file = match open_append(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "AuditFileStore: cannot open {}: {e} — audit logging disabled",
                path.display()
            );
            // Drain the channel so senders are not blocked
            while rx.recv().await.is_some() {}
            return;
        }
    };

    while let Some(draft) = rx.recv().await {
        let mut ev = AuditEventFull {
            id: next_id,
            timestamp: draft.timestamp,
            operation: draft.operation,
            user: draft.user,
            object_uid: draft.object_uid,
            algorithm: draft.algorithm,
            client_ip: draft.client_ip,
            result: draft.result,
            duration_ms: draft.duration_ms,
            prev_hash,
            row_hash: [0_u8; 32],
        };

        // Compute the hash only after all fields are set
        ev.row_hash = compute_row_hash(&ev);

        match write_event(&mut file, &ev) {
            Ok(()) => {
                // Advance chain state
                prev_hash = ev.row_hash;
                next_id += 1;
            }
            Err(e) => {
                warn!(
                    "AuditFileStore: failed to write event id={}: {e} — event dropped",
                    ev.id
                );
                // Do NOT advance id or prev_hash — the next event will reuse
                // the same slot, preserving chain continuity.
            }
        }
    }

    debug!("AuditFileStore: writer loop exited (channel closed)");
}

/// Opens the audit file for appending, creating parent directories if needed.
fn open_append(path: &PathBuf) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Serialises `event` as a single JSONL line and flushes to disk.
fn write_event(file: &mut std::fs::File, event: &AuditEventFull) -> std::io::Result<()> {
    let mut line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    file.write_all(line.as_bytes())?;
    file.flush()
}

// ── Convenience constructors for the middleware ───────────────────────────────

/// Builds an `AuditEventDraft` for a successful KMIP operation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_success_draft(
    operation: impl Into<String>,
    user: impl Into<String>,
    object_uid: Option<String>,
    algorithm: Option<String>,
    client_ip: Option<String>,
    duration_ms: u64,
) -> AuditEventDraft {
    AuditEventDraft {
        timestamp: OffsetDateTime::now_utc(),
        operation: operation.into(),
        user: user.into(),
        object_uid,
        algorithm,
        client_ip,
        result: AuditResult::Success,
        duration_ms,
    }
}

/// Builds an `AuditEventDraft` for a failed KMIP operation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_failure_draft(
    operation: impl Into<String>,
    user: impl Into<String>,
    object_uid: Option<String>,
    algorithm: Option<String>,
    client_ip: Option<String>,
    duration_ms: u64,
    reason: impl Into<String>,
) -> AuditEventDraft {
    AuditEventDraft {
        timestamp: OffsetDateTime::now_utc(),
        operation: operation.into(),
        user: user.into(),
        object_uid,
        algorithm,
        client_ip,
        result: AuditResult::Failure(reason.into()),
        duration_ms,
    }
}
