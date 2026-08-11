//! `AuditStore`: a cheaply cloneable handle to the audit writer task.
//!
//! Backend-agnostic: the chosen `AuditSink` is monomorphised into the writer task at `start` and
//! never appears in this type. That is why `KMS` and `AuditMiddleware` keep holding one concrete
//! `Option<AuditStore>` instead of a `Box<dyn AuditSink>` or an enum.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use cosmian_kms_access::audit::AuditEventDraft;
use cosmian_kms_interfaces::AuditSink;
use cosmian_kms_server_database::PgAuditSink;
use cosmian_logger::{debug, error};
use tokio::sync::{mpsc, oneshot, watch};

use super::{file_sink::FileSink, writer::writer_loop};
use crate::{
    config::{AuditBackendParams, AuditParams},
    error::KmsError,
    result::KResult,
};

/// Message sent to the writer task over the channel.
pub(super) enum WriterMsg {
    /// A draft event to persist.
    Event(AuditEventDraft),
    /// A synchronization barrier: the writer acknowledges once every message enqueued before
    /// this one has been written (and, for `FileSink`, `fsync`'d). Used by tests to await the
    /// writer's progress deterministically instead of sleeping.
    #[cfg_attr(not(test), allow(dead_code))]
    Flush(oneshot::Sender<()>),
}

/// A cheaply cloneable handle to the audit writer task.
///
/// Cloning this value is O(1) — `tokio::sync::mpsc::Sender` is already backed by an internal
/// `Arc`, and `dropped_count` is an `Arc<AtomicU64>`. All clones share the same underlying
/// channel and writer task.
#[derive(Clone)]
pub(crate) struct AuditStore {
    sender: mpsc::Sender<WriterMsg>,
    /// Counts events dropped because the channel was full. Checked by the writer loop to emit a
    /// sentinel event before the next real event.
    dropped_count: Arc<AtomicU64>,
    /// Set by the writer when a sink failure is unrecoverable. Watched by
    /// `start_http_kms_server`, which stops the server: serving requests that are not being
    /// audited would silently break the compliance guarantee the operator enabled this for.
    fatal_rx: watch::Receiver<Option<String>>,
}

impl AuditStore {
    /// Selects the backend, connects it, resumes the chain and spawns the sole writer task.
    ///
    /// Fail-fast by design: an unwritable file, an unreachable database, a chain whose last row
    /// fails verification, or a second KMS instance contending for the same audit database all
    /// abort server startup rather than silently disabling audit logging.
    ///
    /// # Errors
    /// See above; also returns an error when `channel_capacity == 0`.
    pub(crate) async fn start(params: &AuditParams) -> KResult<Self> {
        if params.channel_capacity == 0 {
            return Err(KmsError::ServerError(
                "audit: channel_capacity must be at least 1".to_owned(),
            ));
        }
        match &params.backend {
            AuditBackendParams::File { path } => {
                let sink = FileSink::open(path)?;
                Self::spawn(sink, params.channel_capacity).await
            }
            AuditBackendParams::Postgres { url, instance_id } => {
                let sink = PgAuditSink::connect(url, instance_id)
                    .await
                    .map_err(KmsError::from)?;
                Self::spawn(sink, params.channel_capacity).await
            }
        }
    }

    /// Generic over the sink so the writer loop stays monomorphic — no `dyn` dispatch on the
    /// per-event write path.
    async fn spawn<S: AuditSink + 'static>(mut sink: S, capacity: usize) -> KResult<Self> {
        let head = sink.resume().await.map_err(KmsError::from)?;
        debug!(
            "audit: sink '{}' resuming at id={}, prev_hash={}",
            sink.name(),
            head.next_id,
            hex::encode(head.prev_hash.get(..8).unwrap_or(&head.prev_hash[..]))
        );

        let (tx, rx) = mpsc::channel::<WriterMsg>(capacity);
        let (fatal_tx, fatal_rx) = watch::channel(None);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let dropped_count_for_writer = Arc::clone(&dropped_count);

        tokio::spawn(async move {
            writer_loop(
                sink,
                head.next_id,
                head.prev_hash,
                rx,
                dropped_count_for_writer,
                fatal_tx,
            )
            .await;
        });

        Ok(Self {
            sender: tx,
            dropped_count,
            fatal_rx,
        })
    }

    /// Enqueues one or more draft events for writing. Non-blocking: if the channel is full an
    /// event is dropped and the `dropped_count` counter is incremented. The writer loop drains
    /// that counter before each real event and emits a synthetic `operation = "audit:eviction"`
    /// sentinel that joins the hash chain.
    pub(crate) fn enqueue(&self, drafts: impl IntoIterator<Item = AuditEventDraft>) {
        for draft in drafts {
            match self.sender.try_send(WriterMsg::Event(draft)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    error!("AuditStore: channel full, dropping audit event");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    error!("AuditStore: writer task has stopped, audit event dropped");
                }
            }
        }
    }

    /// Awaits until every event enqueued before this call has been written by the writer task.
    /// Intended for tests and offline tooling that need a deterministic drain point instead of a
    /// fixed sleep. A no-op if the writer task has already stopped.
    #[allow(dead_code, reason = "test-only today; a genuine crate API, not dead")]
    pub(crate) async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(WriterMsg::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Resolves when the writer has declared an unrecoverable sink failure, yielding the reason.
    /// Never resolves if the writer exits cleanly (graceful shutdown) — the caller races this
    /// against normal server shutdown and only acts on this branch.
    pub(crate) async fn wait_fatal(&self) -> String {
        let mut rx = self.fatal_rx.clone();
        loop {
            let current = rx.borrow().clone();
            if let Some(reason) = current {
                return reason;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::{Path, PathBuf};

    use cosmian_kms_access::audit::{AuditEvent, AuditEventDraft, AuditResult, verify_event};
    use time::OffsetDateTime;

    use super::AuditStore;
    use crate::config::{AuditBackendParams, AuditParams};

    const TEST_CAPACITY: usize = 16;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kms_audit_store_test_{}_{label}.jsonl",
            std::process::id()
        ))
    }

    fn file_params(path: &Path) -> AuditParams {
        AuditParams {
            backend: AuditBackendParams::File {
                path: path.to_path_buf(),
            },
            channel_capacity: TEST_CAPACITY,
            trusted_proxy_cidrs: vec![],
        }
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
        }
    }

    fn read_events(path: &Path) -> Vec<AuditEvent> {
        use std::io::BufRead as _;
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
    }

    #[tokio::test]
    async fn enqueue_drops_when_channel_full() {
        let path = temp_path("capacity");
        std::fs::remove_file(&path).ok();

        let store = AuditStore::start(&file_params(&path)).await.unwrap();
        for _ in 0..(TEST_CAPACITY * 2) {
            store.enqueue(std::iter::once(make_draft()));
        }
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert!(events.len() <= TEST_CAPACITY + 1);
        assert!(
            events.len() < TEST_CAPACITY * 2,
            "some events must have been dropped"
        );
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn sentinel_emitted_after_drops() {
        let path = temp_path("sentinel");
        std::fs::remove_file(&path).ok();

        let store = AuditStore::start(&file_params(&path)).await.unwrap();
        for _ in 0..(TEST_CAPACITY * 2) {
            store.enqueue(std::iter::once(make_draft()));
        }
        store.enqueue(std::iter::once(make_draft()));
        store.flush().await;
        drop(store);

        let events = read_events(&path);
        assert_valid_chain(&events);
        let sentinel = events
            .iter()
            .find(|e| e.operation == "audit:eviction")
            .expect("expected an audit:eviction sentinel event");
        match &sentinel.result {
            AuditResult::Failure(msg) => assert!(msg.contains("dropped")),
            AuditResult::Success => panic!("expected Failure, got Success"),
        }

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn chain_resumes_on_restart() {
        let path = temp_path("resume");
        std::fs::remove_file(&path).ok();

        {
            let store = AuditStore::start(&file_params(&path)).await.unwrap();
            for _ in 0..3 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }
        {
            let store = AuditStore::start(&file_params(&path)).await.unwrap();
            for _ in 0..2 {
                store.enqueue(std::iter::once(make_draft()));
            }
            store.flush().await;
        }

        let events = read_events(&path);
        assert_eq!(events.len(), 5);
        for (i, ev) in events.iter().enumerate() {
            assert_eq!(ev.id, i64::try_from(i).unwrap());
        }
        assert_valid_chain(&events);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn start_fails_with_zero_capacity() {
        let path = temp_path("zero_capacity");
        std::fs::remove_file(&path).ok();
        let mut params = file_params(&path);
        params.channel_capacity = 0;

        let result = AuditStore::start(&params).await;
        let Err(err) = result else {
            panic!("AuditStore::start must reject channel_capacity == 0");
        };
        assert!(
            err.to_string()
                .contains("channel_capacity must be at least 1")
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn start_fails_when_path_is_unopenable() {
        let blocker = temp_path("unopenable_blocker");
        std::fs::remove_file(&blocker).ok();
        std::fs::write(&blocker, b"i am a file, not a directory").unwrap();
        let bogus_path = blocker.join("audit.jsonl");

        let result = AuditStore::start(&file_params(&bogus_path)).await;
        assert!(
            result.is_err(),
            "start() must fail when the log file cannot be opened"
        );
        std::fs::remove_file(&blocker).ok();
    }
}
