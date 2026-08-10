//! OTLP log record export for audit events via HTTP/JSON.
//!
//! Architecture
//! ============
#![allow(clippy::doc_link_with_quotes)]
//! * `AuditOtlpLogs` is a cheaply cloneable handle (wraps a channel `Sender`).
//! * A single background tokio task POSTs audit events as OTLP log record JSON
//!   to the configured collector endpoint.
//! * The middleware calls `enqueue()` which is a non-blocking `try_send`.  If
//!   the channel is full, the draft is silently dropped — same behaviour as
//!   the file store.
//!
//! Payload format (OTLP JSON over HTTP)
//! ====================================
//! POST /v1/logs
//! Content-Type: application/json
//! {
//!   "resourceLogs": [{
//!     "scopeLogs": [{
//!       "logRecords": [{
//!         "timeUnixNano": "...",
//!         "severityNumber": 9,
//!         "severityText": "Success",
//!         "body": {"stringValue": "<JSONL event>"},
//!         "attributes": [{"key": "`cef_line`", "value": {"stringValue": "<CEF line>"}}]
//!       }]
//!     }]
//!   }]
//! }

use cosmian_kms_access::audit::{AuditEventDraft, AuditResult};
use cosmian_logger::error;
use tokio::sync::mpsc;

/// Channel capacity for buffered audit-to-OTLP export.
const OTLP_CHANNEL_CAPACITY: usize = 4_096;

/// How many log records to batch before sending.
const BATCH_SIZE: usize = 64;

/// Message sent to the OTLP background writer task.
enum OtlpMsg {
    /// An audit event draft to export.
    Event(AuditEventDraft),
}

/// A cheaply cloneable handle to the OTLP audit log exporter.
#[derive(Clone)]
pub(crate) struct AuditOtlpLogs {
    sender: mpsc::Sender<OtlpMsg>,
}

impl AuditOtlpLogs {
    /// Initialises the OTLP log exporter and spawns the background task.
    pub(crate) fn start(endpoint: &str, allow_insecure: bool) -> Self {
        let endpoint = endpoint.trim_end_matches('/').to_owned();
        let (tx, rx) = mpsc::channel::<OtlpMsg>(OTLP_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            otlp_writer_loop(rx, &endpoint, allow_insecure).await;
        });

        Self { sender: tx }
    }

    /// Enqueues one or more draft events for OTLP export.
    /// Non-blocking: if the channel is full, the event is silently dropped.
    pub(crate) fn enqueue<'a>(&self, drafts: impl IntoIterator<Item = &'a AuditEventDraft>) {
        for draft in drafts {
            drop(self.sender.try_send(OtlpMsg::Event(draft.clone())));
        }
    }
}

/// Background task: receives audit event drafts, batches them, and POSTs
/// as OTLP JSON log records to the configured collector.
async fn otlp_writer_loop(mut rx: mpsc::Receiver<OtlpMsg>, endpoint: &str, allow_insecure: bool) {
    let client = if allow_insecure {
        match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("AuditOtlpLogs: failed to build HTTP client: {e}");
                return;
            }
        }
    } else {
        reqwest::Client::new()
    };

    let otlp_url = format!("{endpoint}/v1/logs");
    let mut batch: Vec<AuditEventDraft> = Vec::with_capacity(BATCH_SIZE);

    loop {
        match rx.recv().await {
            Some(OtlpMsg::Event(draft)) => {
                batch.push(draft);
                if batch.len() >= BATCH_SIZE {
                    send_batch(&client, &otlp_url, &batch).await;
                    batch.clear();
                }
            }
            None => {
                if !batch.is_empty() {
                    send_batch(&client, &otlp_url, &batch).await;
                }
                break;
            }
        }
    }

    // Channel closed — stop.
}

/// Builds and POSTs an OTLP JSON payload for a batch of audit events.
async fn send_batch(client: &reqwest::Client, url: &str, drafts: &[AuditEventDraft]) {
    let records: Vec<serde_json::Value> = drafts.iter().map(build_log_record).collect();

    // OTLP JSON format per https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding
    let payload = serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [{
                    "key": "service.name",
                    "value": { "stringValue": "cosmian_kms" }
                }]
            },
            "scopeLogs": [{
                "scope": {
                    "name": "cosmian_kms_audit",
                    "version": "dev"
                },
                "logRecords": records
            }]
        }]
    });

    match client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                error!(
                    "AuditOtlpLogs: collector returned HTTP {} — {}",
                    resp.status().as_u16(),
                    resp.text().await.unwrap_or_default()
                );
            }
        }
        Err(e) => {
            error!("AuditOtlpLogs: failed to send batch to {url}: {e}");
        }
    }
}

/// Builds a single OTLP log record JSON value from an audit event draft.
fn build_log_record(draft: &AuditEventDraft) -> serde_json::Value {
    use cosmian_kms_access::audit::to_cef_line;

    let nanos = draft
        .timestamp
        .unix_timestamp_nanos()
        .unsigned_abs()
        .to_string();

    let severity_number = match &draft.result {
        AuditResult::Success => 9_u8,     // INFO
        AuditResult::Failure(_) => 17_u8, // ERROR
    };

    let severity_text = match &draft.result {
        AuditResult::Success => "Success",
        AuditResult::Failure(_) => "Failure",
    };

    // Build JSON body string from draft fields
    let body_json = serde_json::json!({
        "timestamp": draft.timestamp.unix_timestamp(),
        "operation": draft.operation,
        "user": draft.user,
        "object_uid": draft.object_uid,
        "algorithm": draft.algorithm,
        "client_ip": draft.client_ip,
        "result": match &draft.result {
            AuditResult::Success => serde_json::Value::String("Success".into()),
            AuditResult::Failure(msg) => serde_json::json!({"Failure": msg}),
        },
        "duration_ms": draft.duration_ms,
        "request_id": draft.request_id.map(|id| id.to_string()),
    });

    let cef_line = to_cef_line(
        &cosmian_kms_access::audit::AuditEvent {
            id: 0,
            timestamp: draft.timestamp,
            operation: draft.operation.clone(),
            user: draft.user.clone(),
            object_uid: draft.object_uid.clone(),
            algorithm: draft.algorithm.clone(),
            client_ip: draft.client_ip.clone(),
            result: draft.result.clone(),
            duration_ms: draft.duration_ms,
            request_id: draft.request_id,
            prev_hash: [0_u8; 32],
            row_hash: [0_u8; 32],
        },
        "dev",
    );

    serde_json::json!({
        "timeUnixNano": nanos,
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": {
            "stringValue": body_json.to_string()
        },
        "attributes": [
            {
                "key": "cef_line",
                "value": { "stringValue": cef_line }
            }
        ]
    })
}
