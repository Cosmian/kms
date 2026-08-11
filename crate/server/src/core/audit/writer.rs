//! The background audit writer task: sole owner of the sink, the id counter, and `prev_hash`.
//! Designed not to panic — errors are logged and the loop continues, except when the sink
//! reports the failure as fatal (see [`cosmian_kms_interfaces::AuditSink::write_failure_is_fatal`]).

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use cosmian_kms_access::audit::{
    AuditEvent, AuditEventDraft, AuditResult, audit_now, compute_row_hash,
};
use cosmian_kms_interfaces::AuditSink;
use cosmian_logger::{debug, error};
use tokio::sync::{mpsc, watch};

use super::store::WriterMsg;

/// Runs until the channel closes (graceful shutdown) or the sink declares a fatal failure.
/// Calls `final_sync()` before exiting on a clean channel close so in-flight events are durable.
/// Returns the sink so tests can inspect what was actually persisted.
pub(super) async fn writer_loop<S: AuditSink>(
    mut sink: S,
    mut next_id: i64,
    mut prev_hash: [u8; 32],
    mut rx: mpsc::Receiver<WriterMsg>,
    dropped_count: Arc<AtomicU64>,
    fatal_tx: watch::Sender<Option<String>>,
) -> S {
    while let Some(msg) = rx.recv().await {
        let draft = match msg {
            WriterMsg::Event(draft) => draft,
            WriterMsg::Flush(ack) => {
                // Every prior message has already been written above; simply acknowledge.
                let _ = ack.send(());
                continue;
            }
        };

        // Emit a sentinel before the real event if any drops occurred since the last write.
        let n_dropped = dropped_count.swap(0, Ordering::Relaxed);
        if n_dropped > 0 {
            let sentinel = make_eviction_sentinel(n_dropped);
            if !write_draft_to_chain(&mut sink, sentinel, &mut next_id, &mut prev_hash, &fatal_tx)
                .await
            {
                return sink;
            }
        }
        if !write_draft_to_chain(&mut sink, draft, &mut next_id, &mut prev_hash, &fatal_tx).await {
            return sink;
        }
    }

    if let Err(e) = sink.final_sync().await {
        error!("AuditStore: sink '{}' final sync failed: {e}", sink.name());
    }
    debug!("AuditStore: writer loop exited (channel closed)");
    sink
}

/// Finalises and writes one draft into the chain, advancing `next_id`/`prev_hash` on success.
///
/// Returns `false` when the writer must stop consuming — the sink declared an unrecoverable
/// failure via `write_failure_is_fatal()` and `fatal_tx` was notified. Returns `true` otherwise,
/// including on a non-fatal write failure (the draft is dropped and the slot reused, matching
/// the historical file-only behaviour).
async fn write_draft_to_chain<S: AuditSink>(
    sink: &mut S,
    draft: AuditEventDraft,
    next_id: &mut i64,
    prev_hash: &mut [u8; 32],
    fatal_tx: &watch::Sender<Option<String>>,
) -> bool {
    let mut ev = AuditEvent {
        id: *next_id,
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

    match sink.write_event(&ev).await {
        Ok(()) => {
            *prev_hash = ev.row_hash;
            *next_id = next_id.checked_add(1).unwrap_or_else(|| {
                error!(
                    "AuditStore: id counter overflow at i64::MAX — audit logging stopped. \
                     Rotate the log file and restart."
                );
                *next_id
            });
            true
        }
        // A failure that reached here survived the sink's own retry budget (PgAuditSink
        // retries internally; FileSink has nothing to retry). Escalate only if the sink says
        // so: losing a database is unrecoverable, whereas a full disk keeps the historical
        // behaviour of logging, reusing the chain slot, and continuing.
        Err(e) if sink.write_failure_is_fatal() => {
            error!(
                "FATAL: audit sink '{}' failed to write event id={}: {e}",
                sink.name(),
                ev.id
            );
            drop(fatal_tx.send(Some(format!(
                "audit sink '{}' write failure: {e}",
                sink.name()
            ))));
            false
        }
        Err(e) => {
            error!(
                "AuditStore: failed to write event id={}: {e} — event dropped",
                ev.id
            );
            // Do NOT advance id or prev_hash — the next event will reuse the same slot,
            // preserving chain continuity.
            true
        }
    }
}

/// Builds a sentinel `AuditEventDraft` recording how many real events were dropped due to
/// channel saturation. Joins the hash chain like any real event.
fn make_eviction_sentinel(n_dropped: u64) -> AuditEventDraft {
    AuditEventDraft {
        timestamp: audit_now(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, atomic::AtomicU64};

    use async_trait::async_trait;
    use cosmian_kms_access::audit::{AuditEvent, AuditEventDraft, AuditResult, verify_event};
    use cosmian_kms_interfaces::{AuditSink, ChainHead, InterfaceError, InterfaceResult};
    use time::OffsetDateTime;
    use tokio::sync::{mpsc, watch};

    use super::{WriterMsg, writer_loop};

    const TEST_CAPACITY: usize = 16;

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

    /// A mock sink that fails `write_event` for calls whose 0-based index satisfies
    /// `should_fail`, and optionally reports the failure as fatal.
    struct FaultySink {
        events: Vec<AuditEvent>,
        call_count: usize,
        should_fail: fn(usize) -> bool,
        fatal: bool,
    }

    impl FaultySink {
        fn new(should_fail: fn(usize) -> bool) -> Self {
            Self {
                events: Vec::new(),
                call_count: 0,
                should_fail,
                fatal: false,
            }
        }

        const fn fatal(mut self) -> Self {
            self.fatal = true;
            self
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
                return Err(InterfaceError::Db("simulated write failure".to_owned()));
            }
            self.events.push(event.clone());
            Ok(())
        }

        fn write_failure_is_fatal(&self) -> bool {
            self.fatal
        }
    }

    /// A single failed write mid-run must not advance the chain: the failed draft is lost, and
    /// the next successful write reuses its `id`/`prev_hash` slot.
    #[tokio::test]
    async fn faulty_sink_error_does_not_advance_chain_and_reuses_slot() {
        let (tx, rx) = mpsc::channel::<WriterMsg>(TEST_CAPACITY);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let (fatal_tx, _fatal_rx) = watch::channel(None);
        let sink = FaultySink::new(|idx| idx == 2);

        let handle = tokio::spawn(writer_loop(
            sink,
            0,
            [0_u8; 32],
            rx,
            dropped_count,
            fatal_tx,
        ));

        for _ in 0..5 {
            tx.send(WriterMsg::Event(make_draft())).await.unwrap();
        }
        drop(tx);

        let sink = handle.await.unwrap();
        assert_eq!(
            sink.events.len(),
            4,
            "one draft must be lost to the injected failure"
        );
        for (i, ev) in sink.events.iter().enumerate() {
            assert_eq!(ev.id, i64::try_from(i).unwrap(), "ids must stay contiguous");
        }
        assert_valid_chain(&sink.events);
    }

    #[tokio::test]
    async fn faulty_sink_all_writes_fail_persists_nothing() {
        let (tx, rx) = mpsc::channel::<WriterMsg>(TEST_CAPACITY);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let (fatal_tx, _fatal_rx) = watch::channel(None);
        let sink = FaultySink::new(|_| true);

        let handle = tokio::spawn(writer_loop(
            sink,
            0,
            [0_u8; 32],
            rx,
            dropped_count,
            fatal_tx,
        ));

        for _ in 0..3 {
            tx.send(WriterMsg::Event(make_draft())).await.unwrap();
        }
        drop(tx);

        let sink = handle.await.unwrap();
        assert!(
            sink.events.is_empty(),
            "no event should be persisted when every write fails"
        );
    }

    /// A sink that reports a write failure as fatal must stop the writer loop immediately and
    /// notify `fatal_tx`, rather than logging and continuing.
    #[tokio::test]
    async fn fatal_sink_stops_the_loop_and_notifies() {
        let (tx, rx) = mpsc::channel::<WriterMsg>(TEST_CAPACITY);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let (fatal_tx, mut fatal_rx) = watch::channel(None);
        let sink = FaultySink::new(|_| true).fatal();

        let handle = tokio::spawn(writer_loop(
            sink,
            0,
            [0_u8; 32],
            rx,
            dropped_count,
            fatal_tx,
        ));

        tx.send(WriterMsg::Event(make_draft())).await.unwrap();
        // The loop stops after the first (fatal) failure, so the second event is never
        // delivered even though the channel stays open — dropping `tx` lets `handle` resolve.
        drop(tx);

        let sink = handle.await.unwrap();
        assert!(sink.events.is_empty());

        fatal_rx.changed().await.ok();
        let reason = fatal_rx.borrow().clone();
        assert!(reason.is_some(), "fatal_tx must be notified");
        assert!(reason.unwrap().contains("write failure"));
    }
}
