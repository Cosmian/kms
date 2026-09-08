//! The background audit writer task: sole owner of the sink, the id counter, and
//! `prev_hash`. Designed not to panic — errors are logged and the loop continues.
//! Generic over [`AuditSink`] so every backend shares this exact steady-state loop;
//! only initialization (see `AuditSink::resume`) differs per backend.

use std::sync::{Arc, atomic::AtomicU64};

use cosmian_kms_access::audit::{AuditEventDraft, AuditResult};
use cosmian_kms_interfaces::AuditSink;
use cosmian_logger::{debug, error};
use time::OffsetDateTime;
use tokio::sync::mpsc;

use super::store::WriterMsg;

/// Minimum interval between "sink at capacity" debug log lines while blocked events keep
/// arriving — avoids flooding the log once a backend-specific cap (e.g. the file
/// backend's `max_size_bytes`) is reached.
const CAPPED_DEBUG_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// The background writer task.  Sole owner of the sink, the id counter, and
/// `prev_hash`.  Designed not to panic — errors are logged and the loop
/// continues.  Calls `final_sync()` before exiting so in-flight events are
/// durable on graceful shutdown.  Returns the sink so tests can inspect what
/// was actually persisted.
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

    // Channel closed (sender dropped on graceful shutdown): ensure all written
    // events are durable before the task exits.
    if let Err(e) = sink.final_sync().await {
        error!("AuditFileStore: final sync failed: {e}");
    }
    debug!("AuditFileStore: writer loop exited (channel closed)");
    sink
}

/// Finalises and writes a single `AuditEventDraft` into the chain, advancing
/// `next_id` and `prev_hash` on success.  Returns the new `next_id`.
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
        details: None,
    }
}
