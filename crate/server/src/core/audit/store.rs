//! `AuditFileStore`: a cheaply cloneable handle to the audit writer task.
//!
//! * `AuditFileStore` is a cheaply cloneable handle (wraps a channel `Sender`).
//! * A single background tokio task is the **sole owner** of the sink (see
//!   `file_sink::FileSink`), the monotonic event counter, and the previous-row hash.
//!   This design avoids any mutex around the file and guarantees write order under
//!   concurrent requests.
//! * The KMS always starts: `start_with_max_size()` returns synchronously and never
//!   blocks on file I/O or lock contention. Recovery, exclusive-lock acquisition, and
//!   opening the file all happen inside `FileSink::resume`, awaited by the spawned task,
//!   never by the caller. Events enqueued in the meantime are genuinely queued (not
//!   dropped) up to the channel's bounded capacity.
//! * The middleware calls `enqueue()` which is a non-blocking `try_send`.  If the
//!   channel is full (beyond the configured capacity) the draft is silently dropped
//!   and an error is logged — we never block the request path.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cosmian_kms_access::audit::AuditEventDraft;
use cosmian_kms_interfaces::AuditSink;
use cosmian_logger::error;
use tokio::sync::{mpsc, oneshot};

use super::{
    file_sink::{AuditWriteState, FileSink},
    writer::writer_loop,
};
use crate::{error::KmsError, result::KResult};

/// Message sent to the writer task over the channel.
pub(super) enum WriterMsg {
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
/// by an internal `Arc`, and `dropped_count`/`write_state` are themselves `Arc`s.
/// All clones share the same underlying channel and writer task.
#[derive(Clone)]
pub(crate) struct AuditFileStore {
    sender: mpsc::Sender<WriterMsg>,
    /// Counts events dropped because the channel was full.
    /// Checked by the writer loop to emit a sentinel event before the next real event.
    dropped_count: Arc<AtomicU64>,
    /// Set by the writer once the configured `max_size_bytes` cap is reached.
    write_state: Arc<AuditWriteState>,
}

impl AuditFileStore {
    /// Initialises the audit file store and spawns the background writer task.
    ///
    /// Returns immediately: the channel is created and handed back synchronously so the
    /// middleware can start enqueueing events right away, even before the writer has
    /// acquired the lock or opened the file. `channel_capacity` is the number of events
    /// that can be buffered before new events are dropped. Must be ≥ 1.
    ///
    /// `max_size_bytes`, when `Some`, stops all writes once the file reaches that many
    /// bytes — see `AuditFileConfig::audit_file_max_size_bytes`. `None` is unlimited.
    ///
    /// Recovery, locking, and opening all happen inside `FileSink::resume`, awaited by
    /// the spawned writer task. This call never blocks on file I/O or lock contention.
    ///
    /// # Errors
    /// Returns an error only if `channel_capacity` is 0 — a pure configuration mistake,
    /// not a runtime condition. Every other fault (I/O, lock contention, log corruption)
    /// is handled inside `FileSink::resume` without aborting startup — see its docs.
    pub(crate) fn start_with_max_size(
        path: &Path,
        channel_capacity: usize,
        max_size_bytes: Option<u64>,
    ) -> KResult<Self> {
        if channel_capacity == 0 {
            return Err(KmsError::ServerError(
                "audit: channel_capacity must be at least 1".to_owned(),
            ));
        }

        let (tx, rx) = mpsc::channel::<WriterMsg>(channel_capacity);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let dropped_count_for_writer = Arc::clone(&dropped_count);
        let write_state = Arc::new(AuditWriteState::new(max_size_bytes));
        let write_state_for_writer = Arc::clone(&write_state);
        let path = path.to_path_buf();

        tokio::spawn(async move {
            let mut sink = FileSink::new(path, write_state_for_writer);
            match sink.resume().await {
                Ok(chain_head) => {
                    writer_loop(
                        sink,
                        chain_head.next_id,
                        chain_head.prev_hash,
                        rx,
                        dropped_count_for_writer,
                    )
                    .await;
                }
                Err(e) => {
                    error!(
                        "AuditFileStore: audit sink failed to resume ({e}) — audit logging is \
                         disabled for this process"
                    );
                }
            }
        });

        Ok(Self {
            sender: tx,
            dropped_count,
            write_state,
        })
    }

    /// Enqueues one or more draft events for writing.  Non-blocking: if the channel is
    /// full an event is dropped and the `dropped_count` counter is incremented.  The writer
    /// loop drains that counter before each real event and emits a synthetic
    /// `operation = "audit:eviction"` sentinel that joins the hash chain — making drops
    /// detectable by `ckms audit verify` and compliance tools.
    ///
    /// If the writer has reported that the configured `max_size_bytes` cap was reached,
    /// every draft is rejected immediately (same observable effect as a full channel) —
    /// the writer will never write them anyway.
    ///
    /// **Note**: for batch requests, `try_send` is called per-draft sequentially.
    /// If the channel fills mid-batch, early drafts are persisted and later ones are
    /// dropped — the sentinel will account for them on the next successful enqueue.
    /// Returns `true` if every draft was successfully queued, `false` if any was dropped.
    pub(crate) fn enqueue(&self, drafts: impl IntoIterator<Item = AuditEventDraft>) -> bool {
        if self.write_state.size_limit_reached.load(Ordering::Relaxed) {
            return false;
        }

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

/// Test-only constructors on `AuditFileStore`.
#[cfg(test)]
impl AuditFileStore {
    /// Same as [`Self::start_with_max_size`] with no file-size cap (unlimited, the
    /// current/default behavior). Only production code goes through
    /// `start_with_max_size` directly (it always has an `Option<u64>` cap to pass,
    /// even when it's `None`); this convenience wrapper is kept for the many tests
    /// that don't care about the cap at all.
    pub(crate) fn start(path: &Path, channel_capacity: usize) -> KResult<Self> {
        Self::start_with_max_size(path, channel_capacity, None)
    }

    /// Creates a store whose channel receiver is immediately dropped.
    /// Every `try_send` returns `TrySendError::Closed` so `enqueue()` always
    /// returns `false` — no race with a live writer draining the channel.
    pub(crate) fn new_disconnected() -> Self {
        let (sender, _rx) = mpsc::channel::<WriterMsg>(1);
        Self {
            sender,
            dropped_count: Arc::new(AtomicU64::new(0)),
            write_state: Arc::new(AuditWriteState::default()),
        }
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

    use async_trait::async_trait;
    use cosmian_kms_access::audit::{
        AuditEvent, AuditEventDraft, AuditResult, compute_row_hash, verify_event,
    };
    use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
    use time::OffsetDateTime;
    use tokio::sync::mpsc;

    use super::{AuditFileStore, WriterMsg};
    use crate::core::audit::{file_sink::lock_file_path, writer::writer_loop};

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
        AuditEventDraft {
            timestamp: OffsetDateTime::now_utc(),
            operation: "Encrypt".to_owned(),
            user: "alice".to_owned(),
            object_uid: Some("obj-1".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: None,
            details: None,
        }
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

    // ── max_size_bytes write-stop cap ─────────────────────────────────────

    /// `None` (the default) stays unlimited: many events past what would be a tiny
    /// cap are all written, proving the cap machinery is fully opt-in.
    #[tokio::test]
    async fn size_cap_none_is_unlimited() {
        let path = temp_path("size_cap_none");
        std::fs::remove_file(&path).ok();

        let store = AuditFileStore::start_with_max_size(&path, TEST_CAPACITY, None).unwrap();
        for _ in 0..5 {
            store.enqueue(std::iter::once(make_draft()));
        }
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert_eq!(events.len(), 5);
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// A file already at (or past) the configured cap when the writer starts must
    /// accept no new event at all — the cap is enforced before any queued event is
    /// processed, not just after a write.
    #[tokio::test]
    async fn size_cap_already_reached_blocks_all_writes() {
        let path = temp_path("size_cap_already_reached");
        std::fs::remove_file(&path).ok();

        // Baseline: 2 valid events, unbounded.
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            store.enqueue(std::iter::once(make_draft()));
            store.enqueue(std::iter::once(make_draft()));
            store.flush().await;
        }
        let baseline = read_events(&path);
        assert_eq!(baseline.len(), 2);
        let cap = std::fs::metadata(&path).unwrap().len();

        // Cap set to exactly the current file length: already at (>=) the cap.
        let store = AuditFileStore::start_with_max_size(&path, TEST_CAPACITY, Some(cap)).unwrap();
        // Synchronize on the writer having performed its startup cap check.
        store.flush().await;

        let queued = store.enqueue(std::iter::once(make_draft()));
        assert!(
            !queued,
            "enqueue() must report false once the file is already at its size cap"
        );
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert_eq!(
            events.len(),
            2,
            "no new event may be written when the file starts already at the cap"
        );
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    /// The event that pushes the file to/past the cap is still persisted (the "one
    /// final event may cross" rule); every event enqueued afterward is rejected and
    /// never written. The chain stays valid through the crossing event.
    #[tokio::test]
    async fn size_cap_allows_crossing_event_then_blocks_further_writes() {
        let path = temp_path("size_cap_crossing");
        std::fs::remove_file(&path).ok();

        // Baseline: 3 valid events, unbounded.
        {
            let store = AuditFileStore::start(&path, TEST_CAPACITY).unwrap();
            for _ in 0..3 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }
        let len_before = std::fs::metadata(&path).unwrap().len();
        // A single event is always far more than 1 byte, so the very next write is
        // guaranteed to cross this cap — regardless of the exact per-event
        // serialized length, which can vary slightly (e.g. timestamp width).
        let cap = len_before + 1;

        // `len_before < cap`: the writer must not be capped on startup.
        let store = AuditFileStore::start_with_max_size(&path, TEST_CAPACITY, Some(cap)).unwrap();
        store.enqueue(std::iter::once(make_draft()));
        store.flush().await;

        let events_after_crossing = read_events(&path);
        assert_eq!(
            events_after_crossing.len(),
            4,
            "the event that crosses the cap must still be persisted"
        );
        assert_valid_chain(&events_after_crossing);

        let queued = store.enqueue(std::iter::once(make_draft()));
        assert!(
            !queued,
            "enqueue() must report false once the cap has been crossed"
        );
        store.flush().await;
        drop(store);

        let events_final = read_events(&path);
        assert_eq!(
            events_final.len(),
            4,
            "no event may be written once the cap has been crossed"
        );
        assert_valid_chain(&events_final);

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

    #[async_trait]
    impl AuditSink for FaultySink {
        fn name(&self) -> &'static str {
            "faulty"
        }

        async fn resume(&mut self) -> InterfaceResult<ChainHead> {
            Ok(ChainHead::EMPTY)
        }

        async fn write_event(&mut self, event: &AuditEvent) -> InterfaceResult<()> {
            let idx = self.call_count;
            self.call_count += 1;
            if (self.should_fail)(idx) {
                return Err(InterfaceError::Default(
                    "simulated write failure".to_owned(),
                ));
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

        let handle =
            tokio::spawn(async move { writer_loop(sink, 0, [0_u8; 32], rx, dropped_count).await });

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

        let handle =
            tokio::spawn(async move { writer_loop(sink, 0, [0_u8; 32], rx, dropped_count).await });

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
