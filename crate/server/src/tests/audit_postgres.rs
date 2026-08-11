//! Cross-backend consistency tests for the audit hash chain: the same drafts, written to the
//! `FileSink` and to `PgAuditSink`, must produce byte-identical `row_hash` sequences.
//!
//! This is the load-bearing guarantee behind exporting/verifying a chain regardless of which
//! backend persisted it — see `.agents/postgres-audit-backend-plan.md`.
//!
//! Live-DB tests are `#[ignore]`d and read `KMS_AUDIT_POSTGRES_URL` at **compile time**
//! (`option_env!`), matching the convention in `cosmian_kms_server_database::tests`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cosmian_kms_access::audit::{AuditEventDraft, AuditResult, audit_now};
use cosmian_kms_server_database::PgAuditReader;
use uuid::Uuid;

use crate::config::{AuditBackendParams, AuditParams};

fn audit_postgres_url() -> String {
    option_env!("KMS_AUDIT_POSTGRES_URL")
        .unwrap_or("postgresql://kms_audit:kms_audit@127.0.0.1:5436/kms_audit")
        .to_owned()
}

fn temp_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "kms_server_audit_pg_test_{}_{label}.jsonl",
        std::process::id()
    ))
}

/// Builds `n` drafts sharing a single `request_id` (as the audit
/// middleware would produce for a batch), so their canonical bytes are fully determined by the
/// draft content alone — identical whichever backend later persists them.
fn make_drafts(n: usize) -> Vec<AuditEventDraft> {
    let request_id = Uuid::new_v4();
    (0..n)
        .map(|i| AuditEventDraft {
            timestamp: audit_now(),
            operation: format!("Op{i}"),
            user: "alice".to_owned(),
            object_uid: Some(format!("uid-{i}")),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: Some(request_id),
        })
        .collect()
}

fn read_file_row_hashes(path: &std::path::Path) -> Vec<[u8; 32]> {
    use std::io::BufRead as _;
    let file = std::fs::File::open(path).unwrap();
    std::io::BufReader::new(file)
        .lines()
        .filter_map(|l| {
            let l = l.unwrap();
            if l.trim().is_empty() {
                None
            } else {
                let ev: cosmian_kms_access::audit::AuditEvent = serde_json::from_str(&l).unwrap();
                Some(ev.row_hash)
            }
        })
        .collect()
}

#[tokio::test]
#[ignore = "Requires a running PostgreSQL instance (KMS_AUDIT_POSTGRES_URL)"]
async fn same_draft_yields_same_row_hash_on_both_backends() {
    let drafts = make_drafts(5);

    // File backend
    let file_path = temp_path("cross_backend");
    std::fs::remove_file(&file_path).ok();
    let file_store = crate::core::audit::AuditStore::start(&AuditParams {
        backend: AuditBackendParams::File {
            path: file_path.clone(),
        },
        channel_capacity: 128,
        trusted_proxy_cidrs: vec![],
    })
    .await
    .unwrap();
    file_store.enqueue(drafts.clone());
    file_store.flush().await;
    drop(file_store);
    let file_hashes = read_file_row_hashes(&file_path);
    std::fs::remove_file(&file_path).ok();

    // PostgreSQL backend, same drafts
    let instance_id = format!("test-cross-backend-{}", Uuid::new_v4());
    let pg_store = crate::core::audit::AuditStore::start(&AuditParams {
        backend: AuditBackendParams::Postgres {
            url: audit_postgres_url(),
            instance_id: instance_id.clone(),
        },
        channel_capacity: 128,
        trusted_proxy_cidrs: vec![],
    })
    .await
    .unwrap();
    pg_store.enqueue(drafts);
    pg_store.flush().await;
    drop(pg_store);

    let reader = PgAuditReader::connect(&audit_postgres_url()).await.unwrap();
    let pg_events = reader.events_for_instance(&instance_id).await.unwrap();
    let pg_hashes: Vec<[u8; 32]> = pg_events.iter().map(|e| e.row_hash).collect();

    assert_eq!(
        file_hashes.len(),
        5,
        "file backend must have persisted all 5 drafts"
    );
    assert_eq!(
        file_hashes, pg_hashes,
        "the same drafts must produce byte-identical row_hash sequences on both backends"
    );
}
