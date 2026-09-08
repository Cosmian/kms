//! The background audit writer task: sole owner of the sink, the id counter, and
//! `prev_hash`. Designed not to panic — errors are logged and the loop continues.

use std::{
    path::Path,
    sync::{Arc, atomic::AtomicU64},
};

use cosmian_kms_access::audit::{AuditEvent, AuditEventDraft, AuditResult, compute_row_hash};
use cosmian_logger::{debug, error};
use time::OffsetDateTime;
use tokio::sync::mpsc;

use super::{
    file_sink::{AuditSink, AuditWriteState, CAPPED_DEBUG_LOG_INTERVAL, enforce_size_cap},
    store::WriterMsg,
};

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
    write_state: Arc<AuditWriteState>,
    path: &Path,
) -> S {
    enforce_size_cap(&sink, &write_state, path);
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

        if write_state
            .size_limit_reached
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let now = std::time::Instant::now();
            let should_log = last_capped_log
                .is_none_or(|logged_at| now.duration_since(logged_at) >= CAPPED_DEBUG_LOG_INTERVAL);
            if should_log {
                debug!(
                    "AuditFileStore: audit log {} is at its max_size_bytes cap — event dropped",
                    path.display()
                );
                last_capped_log = Some(now);
            }
            continue;
        }

        // Emit a sentinel before the real event if any drops occurred since the last write.
        let n_dropped = dropped_count.swap(0, std::sync::atomic::Ordering::Relaxed);
        if n_dropped > 0 {
            let sentinel = make_eviction_sentinel(n_dropped);
            next_id = write_draft_to_chain(&mut sink, sentinel, next_id, &mut prev_hash);
            enforce_size_cap(&sink, &write_state, path);
        }
        if write_state
            .size_limit_reached
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // The sentinel write alone just crossed the cap: writing the real draft too
            // would overshoot the documented "one final event may cross" rule by a
            // second event. Count it as dropped so a future sentinel reports it.
            dropped_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            next_id = write_draft_to_chain(&mut sink, draft, next_id, &mut prev_hash);
            enforce_size_cap(&sink, &write_state, path);
        }
    }

    // Channel closed (sender dropped on graceful shutdown): ensure all written
    // events are durable before the task exits.
    if let Err(e) = sink.final_sync() {
        error!("AuditFileStore: final sync failed: {e}");
    }
    debug!("AuditFileStore: writer loop exited (channel closed)");
    sink
}

/// Finalises and writes a single `AuditEventDraft` into the chain, advancing
/// `next_id` and `prev_hash` on success.  Returns the new `next_id`.
pub(super) fn write_draft_to_chain<S: AuditSink>(
    sink: &mut S,
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
        details: draft.details,
        prev_hash: *prev_hash,
        row_hash: [0_u8; 32],
    };
    ev.row_hash = compute_row_hash(&ev);

    match sink.write_event(&ev) {
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
        details: None,
    }
}
