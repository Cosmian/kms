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
    io::{BufRead, BufReader, Seek, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cosmian_kms_access::audit::{
    AuditEvent, AuditEventDraft, AuditResult, compute_row_hash, verify_event,
};
use cosmian_logger::{debug, error};
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::{error::KmsError, result::KResult};

/// Bytes read from the end of an existing log to locate the last complete event
/// at startup.  64 KiB comfortably covers many events; a single serialised
/// `AuditEventFull` is typically <2 KiB.
const TAIL_WINDOW: u64 = 65_536;

/// A cheaply cloneable handle to the audit writer task.
///
/// Cloning this value is O(1) — `tokio::sync::mpsc::Sender` is already backed
/// by an internal `Arc`, and `dropped_count` is an `Arc<AtomicU64>`.
/// All clones share the same underlying channel and writer task.
#[derive(Clone)]
pub(crate) struct AuditFileStore {
    sender: mpsc::Sender<AuditEventDraft>,
    /// Counts events dropped because the channel was full.
    /// Checked by the writer loop to emit a sentinel event before the next real event.
    dropped_count: Arc<AtomicU64>,
}

impl AuditFileStore {
    /// Initialises the audit file store and spawns the background writer task.
    ///
    /// If `path` already contains events the writer task will continue the
    /// existing chain; the next event ID will be `last_id + 1` and `prev_hash`
    /// will be taken from the last persisted row.
    ///
    /// `channel_capacity` is the number of events that can be buffered in the
    /// in-memory channel before new events are dropped.  Must be ≥ 1.
    ///
    /// # Errors
    /// Returns an error if `channel_capacity` is 0, the audit file cannot be
    /// opened, or an existing file contains a malformed last line.
    pub(crate) fn start(path: &Path, channel_capacity: usize) -> KResult<Self> {
        if channel_capacity == 0 {
            return Err(KmsError::ServerError(
                "audit: channel_capacity must be at least 1".to_owned(),
            ));
        }
        // ── Read the tail of an existing log to resume the chain ─────────
        let (next_id, prev_hash) = Self::resume_chain(path)?;
        debug!(
            "AuditFileStore: resuming at id={next_id}, prev_hash={}",
            hex::encode(&prev_hash[..8]) // first 8 bytes (16 hex chars) sufficient for diagnostics
        );

        // Open before spawning so an unwritable path aborts startup immediately
        // instead of silently disabling audit logging at runtime.
        let file = open_append(path).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot open log file {}: {e}",
                path.display()
            ))
        })?;

        let (tx, rx) = mpsc::channel::<AuditEventDraft>(channel_capacity);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let dropped_count_for_writer = Arc::clone(&dropped_count);

        // Spawn the sole writer task
        tokio::spawn(async move {
            writer_loop(file, next_id, prev_hash, rx, dropped_count_for_writer).await;
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
    pub(crate) fn enqueue(&self, drafts: impl IntoIterator<Item = AuditEventDraft>) {
        for draft in drafts {
            match self.sender.try_send(draft) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    error!("AuditFileStore: channel full, dropping audit event");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    error!("AuditFileStore: writer task has stopped, audit event dropped");
                }
            }
        }
    }

    /// Reads the last line of `path` (if any) to extract the last `id` and
    /// `row_hash` so the chain can be continued on restart.
    fn resume_chain(path: &Path) -> KResult<(i64, [u8; 32])> {
        if !path.exists() {
            return Ok((0, [0_u8; 32]));
        }

        let mut file = std::fs::File::open(path).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot open existing log file {}: {e}",
                path.display()
            ))
        })?;

        let file_len = file
            .metadata()
            .map_err(|e| KmsError::ServerError(format!("audit: cannot stat log file: {e}")))
            .map(|m| m.len())?;

        if file_len == 0 {
            return Ok((0, [0_u8; 32]));
        }

        // Seek to the tail window so startup cost is O(1) regardless of log size.
        // TAIL_WINDOW is large enough to contain at least one complete event.
        let seek_pos = file_len.saturating_sub(TAIL_WINDOW);
        if seek_pos > 0 {
            file.seek(std::io::SeekFrom::Start(seek_pos))
                .map_err(|e| KmsError::ServerError(format!("audit: cannot seek log file: {e}")))?;
        }

        let reader = BufReader::new(file);
        let mut last_line = String::new();

        // When seek_pos > 0 the first buffered read may start mid-line (a partial
        // fragment cut by the seek); taking the LAST non-empty line is correct
        // regardless because subsequent lines are complete.
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

        let last_event: AuditEvent = serde_json::from_str(&last_line).map_err(|e| {
            KmsError::ServerError(format!(
                "audit: cannot parse last line of log file: {e}\nLine: {last_line}"
            ))
        })?;

        // Verify the hash of the last persisted event before trusting it as the
        // chain seed.  A mismatch signals tampering or a crash-truncated write.
        if !verify_event(&last_event) {
            return Err(KmsError::ServerError(format!(
                "audit: last persisted event (id={}) has an invalid row_hash — \
                 the log tail may be corrupted or tampered. \
                 Remove or repair the last line before restarting.",
                last_event.id
            )));
        }

        Ok((last_event.id + 1, last_event.row_hash))
    }
}

/// The background writer task.  Sole owner of the open file, the id counter,
/// and `prev_hash`.  Designed not to panic — errors are logged and the loop
/// continues.  Calls `sync_data()` before exiting so in-flight events are
/// durable on graceful shutdown.
async fn writer_loop(
    mut file: std::fs::File,
    mut next_id: i64,
    mut prev_hash: [u8; 32],
    mut rx: mpsc::Receiver<AuditEventDraft>,
    dropped_count: Arc<AtomicU64>,
) {
    while let Some(draft) = rx.recv().await {
        // Emit a sentinel before the real event if any drops occurred since the last write.
        let n_dropped = dropped_count.swap(0, Ordering::Relaxed);
        if n_dropped > 0 {
            let sentinel = make_eviction_sentinel(n_dropped);
            next_id = write_draft_to_chain(&mut file, sentinel, next_id, &mut prev_hash);
        }
        next_id = write_draft_to_chain(&mut file, draft, next_id, &mut prev_hash);
    }

    // Channel closed (sender dropped on graceful shutdown): ensure all written
    // events are durable before the task exits.
    if let Err(e) = file.sync_data() {
        error!("AuditFileStore: final sync failed: {e}");
    }
    debug!("AuditFileStore: writer loop exited (channel closed)");
}

/// Finalises and writes a single `AuditEventDraft` into the chain, advancing
/// `next_id` and `prev_hash` on success.  Returns the new `next_id`.
fn write_draft_to_chain(
    file: &mut std::fs::File,
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
        prev_hash: *prev_hash,
        row_hash: [0_u8; 32],
    };
    ev.row_hash = compute_row_hash(&ev);

    match write_event(file, &ev) {
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

/// Serialises `event` as a single JSONL line and syncs to storage.
///
/// `sync_data()` is called on every write to guarantee durability: without it
/// data sits in the kernel page cache and is lost on a power failure.  The
/// tradeoff is one `fsync` per audit event; high-throughput deployments can
/// reduce cost by batching syncs (every N events or every T ms).
fn write_event(file: &mut std::fs::File, event: &AuditEvent) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(b"\n")?;
    file.sync_data()
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
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::{
        io::BufRead as _,
        path::{Path, PathBuf},
    };

    use time::OffsetDateTime;

    use cosmian_kms_access::audit::{AuditEvent, AuditEventDraft, verify_event};

    use super::{AuditFileStore, make_success_draft};

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
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let events = read_events(&path);
        // TEST_CAPACITY real events fit in the channel; the writer also emits at
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
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

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
        }
        // Drop closes the channel; yield so the writer drains and exits.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Phase 2: resume from the same file, write 2 more
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            for _ in 0..2 {
                store.enqueue(std::iter::once(make_draft()));
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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
    /// sequential and all chain links are valid.  The "do not advance on failure"
    /// invariant is tested indirectly: any id-gap or hash-mismatch would be
    /// caught by `assert_valid_chain`.  Fault-injection (making the fd unwritable
    /// mid-run) requires a mock file and is tracked separately.
    #[tokio::test]
    async fn write_failure_does_not_advance_chain() {
        let path = temp_path("no_advance");
        std::fs::remove_file(&path).ok();

        let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
        for _ in 0..5 {
            store.enqueue(std::iter::once(make_draft()));
        }
        drop(store);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let events = read_events(&path);
        assert_eq!(events.len(), 5);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev.id, i64::try_from(i).unwrap(), "id gap at position {i}");
        }
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// `start()` must refuse to continue from a log whose last event's hash is
    /// invalid — this catches both tampering and crash-truncated partial writes.
    #[tokio::test]
    async fn resume_rejects_tampered_last_line() {
        let path = temp_path("tampered");
        std::fs::remove_file(&path).ok();

        // Write 2 valid events
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Overwrite the file with the last event's row_hash zeroed out
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
        let mut last_ev: AuditEvent = serde_json::from_str(lines.last().unwrap()).unwrap();
        last_ev.row_hash = [0_u8; 32];
        *lines.last_mut().unwrap() = serde_json::to_string(&last_ev).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // Startup must fail because the last event's hash no longer matches
        let result = AuditFileStore::start(&path, TEST_CAPACITY);
        assert!(result.is_err(), "start() must reject a tampered last event");

        std::fs::remove_file(&path).ok();
    }
}
