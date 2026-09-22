//! Shared audit writer loop.
//!
//! The task owns the sink and chain head; backends provide persistence and recovery.

use std::sync::{Arc, atomic::AtomicU64};

use cosmian_kms_access::audit::{AuditEventDraft, AuditResult, audit_now};
use cosmian_kms_interfaces::AuditSink;
use cosmian_logger::{debug, error};
use tokio::sync::mpsc;

use super::store::WriterMsg;

/// Minimum interval between capacity warnings.
const CAPPED_DEBUG_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Consumes queued events and returns the sink after shutdown synchronisation.
pub(super) async fn writer_loop<S: AuditSink>(
    mut sink: S,
    mut next_id: i64,
    mut prev_hash: [u8; 32],
    mut rx: mpsc::Receiver<WriterMsg>,
    dropped_count: Arc<AtomicU64>,
) -> S {
    let mut last_capped_log: Option<std::time::Instant> = None;

    while let Some(msg) = rx.recv().await {
        let draft = match msg {
            WriterMsg::Event(draft) => *draft,
            WriterMsg::Flush(ack) => {
                // Every prior message has already been written above; simply
                // acknowledge. Ignore a dropped receiver (caller stopped waiting).
                let _ = ack.send(());
                continue;
            }
        };

        if sink.is_write_capacity_exceeded() {
            let now = std::time::Instant::now();
            let should_log = last_capped_log
                .is_none_or(|logged_at| now.duration_since(logged_at) >= CAPPED_DEBUG_LOG_INTERVAL);
            if should_log {
                debug!(
                    "AuditFileStore: sink '{}' is at capacity — event dropped",
                    sink.name()
                );
                last_capped_log = Some(now);
            }
            continue;
        }

        // Emit a sentinel before the real event if any drops occurred since the last write.
        let n_dropped = dropped_count.swap(0, std::sync::atomic::Ordering::Relaxed);
        if n_dropped > 0 {
            let sentinel = make_eviction_sentinel(n_dropped);
            next_id = write_draft_to_chain(&mut sink, sentinel, next_id, &mut prev_hash).await;
        }
        if sink.is_write_capacity_exceeded() {
            // The sentinel write alone just crossed the cap: writing the real draft too
            // would overshoot the documented "one final event may cross" rule by a
            // second event. Count it as dropped so a future sentinel reports it.
            dropped_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            next_id = write_draft_to_chain(&mut sink, draft, next_id, &mut prev_hash).await;
        }
    }

    if let Err(e) = sink.final_sync().await {
        error!("AuditFileStore: final sync failed: {e}");
    }
    debug!("AuditFileStore: writer loop exited (channel closed)");
    sink
}

/// Writes one draft and advances the chain head only on success.
pub(super) async fn write_draft_to_chain<S: AuditSink>(
    sink: &mut S,
    draft: AuditEventDraft,
    next_id: i64,
    prev_hash: &mut [u8; 32],
) -> i64 {
    let event = draft.finalize(next_id, *prev_hash);

    match sink.write_event_atomic(&event).await {
        Ok(()) => {
            *prev_hash = event.row_hash;
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
                event.id
            );
            // Reuse this chain position after a failed write.
            next_id
        }
    }
}

/// Builds a chained sentinel recording events dropped by channel saturation.
fn make_eviction_sentinel(n_dropped: u64) -> AuditEventDraft {
    AuditEventDraft {
        // Every other production draft uses `audit_now()`, truncated to the microsecond
        // resolution PostgreSQL's TIMESTAMPTZ stores — a nanosecond timestamp here would
        // re-hash differently after a PostgreSQL round trip and falsely report tampering.
        timestamp: audit_now(),
        operation: "audit:eviction".to_owned(),
        user: "server".to_owned(),
        object_uid: None,
        algorithm: None,
        client_ip: None,
        result: AuditResult::Failure(format!("{n_dropped} events dropped (channel full)")),
        duration_ms: 0,
        request_id: None,
        details: None,
    }
}
