#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use actix_web::{
    http::StatusCode,
    test::{self as actix_test, call_service},
};
use cosmian_kms_access::audit::{AuditResult, to_cef_line, verify_chain_link, verify_event};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{BlockCipherMode, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Decrypt, Encrypt, Operation},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
    ttlv::{KmipFlavor, to_ttlv},
};
use cosmian_logger::log_init;
use zeroize::Zeroizing;

use crate::{
    result::KResult,
    tests::test_utils::{self, post_2_1, post_kmip_binary, post_kmip_json},
};

fn temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kms_audit_e2e_{}_{label}.jsonl",
        std::process::id()
    ))
}

/// End-to-end audit chain test.
///
/// Sends five KMIP operations through a live in-process KMS with `AuditMiddleware`
/// wired in, then reads the resulting JSONL file and verifies:
///  * Six events were recorded:
///    [0] Create, [1] Encrypt, [2] Decrypt-failure,
///    [3] batch-Create, [4] batch-Locate  ← two events from one `RequestMessage`
///    [5] standalone-Locate
///  * Per-item operation names, results, and `object_uid` are correct.
///  * Events [3] and [4] share the same `request_id` (same batch).
///  * Event [3]'s `request_id` differs from event [0]'s (different HTTP requests).
///  * All single-op events carry a `request_id`.
///  * The hash chain is intact (`verify_event` + `verify_chain_link`).
///  * Every event produces a well-formed CEF line (`to_cef_line`).
#[tokio::test]
async fn audit_records_create_encrypt_failure_and_batch() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let path = temp_path("e2e_chain");
    let (app, store) = test_utils::test_app_with_audit(&path).await;
    let fut = async {
        // 1. Create AES-256-GCM key (FIPS-approved)
        let create_request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let create_response: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::CreateResponse =
            post_2_1(&app, create_request).await?;
        let uid = create_response.unique_identifier;

        // 2. Encrypt with the created key (AES-GCM)
        let encrypt_request = Encrypt {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..CryptographicParameters::default()
            }),
            data: Some(Zeroizing::new(b"hello audit".to_vec())),
            ..Default::default()
        };
        let _enc_resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::EncryptResponse =
            post_2_1(&app, encrypt_request).await?;

        // 3. Decrypt with a non-existent key → OperationFailed (Failure event)
        let bad_uid =
            UniqueIdentifier::TextString("00000000-0000-0000-0000-000000000000".to_owned());
        let decrypt_request = cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Decrypt {
            unique_identifier: Some(bad_uid),
            data: Some(b"ciphertext".to_vec()),
            ..Default::default()
        };
        // Failure is expected; ignore the Err
        drop(
            post_2_1::<_, _, cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::DecryptResponse, _>(
                &app,
                decrypt_request,
            )
            .await,
        );

        // 4. Batch: Create + Locate in one RequestMessage
        let batch_create = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let batch_request = RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 1,
                },
                maximum_response_size: Some(9999),
                batch_count: 2,
                ..Default::default()
            },
            batch_item: vec![
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Create(batch_create),
                )),
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Locate(Box::default()),
                )),
            ],
        };
        let _batch_resp = post_kmip_json(&app, &batch_request).await?;

        // 5. Standalone Locate → ensures a single-op "Locate" operation also appears
        //    in the audit log (not just as part of a batch "Create+Locate").
        let locate_request =
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Locate::default();
        let _locate_resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::LocateResponse =
            post_2_1(&app, locate_request).await?;

        Ok::<UniqueIdentifier, crate::error::KmsError>(uid)
    };

    let uid = Box::pin(fut).await?;

    // Deterministic drain barrier instead of a fixed sleep: once flush()
    // returns, every enqueued event has been written (and synced).
    store.flush().await;

    // Parse and validate the audit log
    let file = std::fs::File::open(&path).expect("audit file not created");
    let events: Vec<cosmian_kms_access::audit::AuditEvent> =
        std::io::BufRead::lines(std::io::BufReader::new(file))
            .filter_map(|l| {
                let l = l.unwrap();
                if l.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str(&l).unwrap())
                }
            })
            .collect();

    assert_eq!(
        events.len(),
        6,
        "expected 6 audit events, got {}",
        events.len()
    );

    // Operation names
    assert_eq!(events[0].operation, "Create", "event 0");
    assert_eq!(events[1].operation, "Encrypt", "event 1");
    assert_eq!(events[2].operation, "Decrypt", "event 2");
    assert_eq!(events[3].operation, "Create", "event 3 (batch-Create)");
    assert_eq!(events[4].operation, "Locate", "event 4 (batch-Locate)");
    assert_eq!(events[5].operation, "Locate", "event 5 (standalone)");

    // Results
    assert_eq!(
        events[0].result,
        AuditResult::Success,
        "event 0 should be Success"
    );
    assert_eq!(
        events[1].result,
        AuditResult::Success,
        "event 1 should be Success"
    );
    assert!(
        matches!(&events[2].result, AuditResult::Failure(_)),
        "event 2 should be Failure, got {:?}",
        events[2].result
    );
    assert_eq!(
        events[3].result,
        AuditResult::Success,
        "event 3 should be Success"
    );
    assert_eq!(
        events[4].result,
        AuditResult::Success,
        "event 4 should be Success"
    );
    assert_eq!(
        events[5].result,
        AuditResult::Success,
        "event 5 (standalone Locate) should be Success"
    );

    // Object UIDs: Create fills it from the response; Encrypt/Decrypt read it from the request
    let uid_str = uid.to_string();
    assert_eq!(
        events[0].object_uid.as_deref(),
        Some(uid_str.as_str()),
        "event 0 uid"
    );
    assert_eq!(
        events[1].object_uid.as_deref(),
        Some(uid_str.as_str()),
        "event 1 uid"
    );
    assert_eq!(
        events[2].object_uid.as_deref(),
        Some("00000000-0000-0000-0000-000000000000"),
        "event 2 uid"
    );
    // batch-Create: UID backfilled from the response
    assert!(
        events[3].object_uid.is_some(),
        "event 3 (batch-Create) should have a uid"
    );

    // request_id: batch items [3] and [4] share the same request_id
    assert!(
        events[3].request_id.is_some(),
        "event 3 must have request_id"
    );
    assert!(
        events[4].request_id.is_some(),
        "event 4 must have request_id"
    );
    assert_eq!(
        events[3].request_id, events[4].request_id,
        "batch items share the same request_id"
    );
    assert_ne!(
        events[3].request_id, events[0].request_id,
        "different HTTP requests must have different request_ids"
    );
    // All single-op events carry a request_id
    for (i, ev) in events.iter().enumerate() {
        assert!(
            ev.request_id.is_some(),
            "event {i} should have a request_id"
        );
    }

    // Hash chain integrity
    let mut prev = None;
    for ev in &events {
        assert!(
            verify_event(ev),
            "hash integrity failed for event id={}",
            ev.id
        );
        assert!(
            verify_chain_link(ev, prev),
            "chain link broken at event id={}",
            ev.id
        );
        prev = Some(ev);
    }

    // Client IP is None under actix_web::test (no real TCP peer).
    // This documents the test-harness limitation: `peer_addr()` returns None,
    // so `extract_client_ip` falls back to None. Real deployments with TLS/TCP
    // will populate this field. This assertion locks in the current behaviour
    // so a future refactor doesn't claim to test client_ip capture without it actually working.
    for ev in &events {
        assert!(
            ev.client_ip.is_none(),
            "actix_web::test has no peer_addr; client_ip must be None for event id={}",
            ev.id
        );
    }

    // CEF output sanity — every event must produce a valid CEF line
    for ev in &events {
        let cef = to_cef_line(ev, "test");
        assert!(
            cef.starts_with("CEF:0|Cosmian|KMS|test|"),
            "unexpected CEF header for event id={}: {cef}",
            ev.id
        );
        // Events with request_id must include cs5
        if ev.request_id.is_some() {
            assert!(
                cef.contains("cs5Label=requestId"),
                "CEF missing cs5Label for event id={}: {cef}",
                ev.id
            );
        }
    }

    Ok(())
}

/// Wraps a single KMIP `Operation` in a `RequestMessage`.
///
/// Binary TTLV requests always deserialize as a `RequestMessage` server-side
/// (`handle_ttlv_bytes_inner` calls `from_ttlv::<RequestMessage>` unconditionally),
/// unlike `/kmip/2_1` which accepts a bare operation TTLV. So every binary request
/// in this test, even a "single" one, has to go through this wrapper.
fn single_op_message(op: Operation) -> RequestMessage {
    RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(op),
        )],
    }
}

/// Extracts the `unique_identifier` from a `CreateResponse` in the first batch item.
fn created_uid(response: &ResponseMessage) -> UniqueIdentifier {
    let ResponseMessageBatchItemVersioned::V21(item) = &response.batch_item[0] else {
        panic!("expected a V21 response batch item");
    };
    let Some(Operation::CreateResponse(create_response)) = &item.response_payload else {
        panic!(
            "expected a CreateResponse payload, got {:?}",
            item.response_payload
        );
    };
    create_response.unique_identifier.clone()
}

/// End-to-end audit test over the binary TTLV wire format (`application/octet-stream`),
/// the encoding used by native KMIP clients (HSMs, other vendors' libraries) rather
/// than the JSON convenience endpoints. Mirrors
/// `audit_records_create_encrypt_failure_and_batch` step for step, so `SEC-01`
/// (binary responses never reached `inject_response_uid`) is covered for both
/// single-op and batch object UIDs.
///
/// Every binary KMIP request is wire-tagged `RequestMessage` (even a "single" op),
/// so it always goes through the batch fan-out path in `AuditMiddleware`. That path
/// derives each item's `AuditResult` from the KMIP response's `ResultStatus`, not
/// from the (always-200) HTTP status of `kmip_binary`. Before the `SEC-01` fix,
/// `inject_response_uid` was never called for binary, so that per-item result was
/// never backfilled and every binary event silently fell back to the generic
/// HTTP-200-derived `Success`, even for a request whose KMIP payload failed. The
/// `events[2]` assertion below (`Decrypt` with a bogus UID) is what would have
/// caught that: the result must be `Failure`, not `Success`.
#[tokio::test]
async fn audit_records_binary_create_encrypt_failure_and_batch() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let path = temp_path("e2e_chain_binary");
    let (app, store) = test_utils::test_app_with_audit(&path).await;
    let fut = async {
        // 1. Create AES-256-GCM key (FIPS-approved), sent as binary TTLV.
        let create_request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let create_response = post_kmip_binary(
            &app,
            &single_op_message(Operation::Create(create_request)),
            KmipFlavor::Kmip2,
        )
        .await?;
        let uid = created_uid(&create_response);

        // 2. Encrypt with the created key (AES-GCM)
        let encrypt_request = Encrypt {
            unique_identifier: Some(uid.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..CryptographicParameters::default()
            }),
            data: Some(Zeroizing::new(b"hello audit binary".to_vec())),
            ..Default::default()
        };
        let _encrypt_response = post_kmip_binary(
            &app,
            &single_op_message(Operation::Encrypt(Box::new(encrypt_request))),
            KmipFlavor::Kmip2,
        )
        .await?;

        // 3. Decrypt with a non-existent key → the response batch item carries
        //    ResultStatus = OperationFailed, but the HTTP status is still 200.
        let bad_uid =
            UniqueIdentifier::TextString("00000000-0000-0000-0000-000000000000".to_owned());
        let decrypt_request = Decrypt {
            unique_identifier: Some(bad_uid),
            data: Some(b"ciphertext".to_vec()),
            ..Default::default()
        };
        let decrypt_response = post_kmip_binary(
            &app,
            &single_op_message(Operation::Decrypt(Box::new(decrypt_request))),
            KmipFlavor::Kmip2,
        )
        .await?;
        let ResponseMessageBatchItemVersioned::V21(decrypt_item) = &decrypt_response.batch_item[0]
        else {
            panic!("expected a V21 response batch item");
        };
        assert_ne!(
            decrypt_item.result_status,
            ResultStatusEnumeration::Success,
            "decrypting with a bogus uid should fail at the KMIP level"
        );

        // 4. Batch: Create + Locate in one RequestMessage
        let batch_create = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let batch_request = RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 1,
                },
                maximum_response_size: Some(9999),
                batch_count: 2,
                ..Default::default()
            },
            batch_item: vec![
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Create(batch_create),
                )),
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Locate(Box::default()),
                )),
            ],
        };
        let _batch_resp = post_kmip_binary(&app, &batch_request, KmipFlavor::Kmip2).await?;

        // 5. Standalone Locate → ensures a single-op "Locate" operation also appears
        //    in the audit log (not just as part of a batch "Create+Locate").
        let _locate_resp = post_kmip_binary(
            &app,
            &single_op_message(Operation::Locate(Box::default())),
            KmipFlavor::Kmip2,
        )
        .await?;

        Ok::<UniqueIdentifier, crate::error::KmsError>(uid)
    };

    let uid = Box::pin(fut).await?;

    // Deterministic drain barrier instead of a fixed sleep.
    store.flush().await;

    let file = std::fs::File::open(&path).expect("audit file not created");
    let events: Vec<cosmian_kms_access::audit::AuditEvent> =
        std::io::BufRead::lines(std::io::BufReader::new(file))
            .filter_map(|l| {
                let l = l.unwrap();
                if l.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str(&l).unwrap())
                }
            })
            .collect();

    assert_eq!(
        events.len(),
        6,
        "expected 6 audit events, got {}",
        events.len()
    );

    assert_eq!(events[0].operation, "Create", "event 0");
    assert_eq!(events[1].operation, "Encrypt", "event 1");
    assert_eq!(events[2].operation, "Decrypt", "event 2");
    assert_eq!(events[3].operation, "Create", "event 3 (batch-Create)");
    assert_eq!(events[4].operation, "Locate", "event 4 (batch-Locate)");
    assert_eq!(events[5].operation, "Locate", "event 5 (standalone)");

    assert_eq!(events[0].result, AuditResult::Success, "event 0");
    assert_eq!(events[1].result, AuditResult::Success, "event 1");
    assert!(
        matches!(&events[2].result, AuditResult::Failure(_)),
        "event 2 should be Failure (this is the assertion SEC-01 broke silently \
         for binary requests), got {:?}",
        events[2].result
    );
    assert_eq!(events[3].result, AuditResult::Success, "event 3");
    assert_eq!(events[4].result, AuditResult::Success, "event 4");
    assert_eq!(events[5].result, AuditResult::Success, "event 5");

    // Object UIDs: the whole point of SEC-01 — binary responses now populate this too.
    let uid_str = uid.to_string();
    assert_eq!(
        events[0].object_uid.as_deref(),
        Some(uid_str.as_str()),
        "event 0 uid"
    );
    assert_eq!(
        events[1].object_uid.as_deref(),
        Some(uid_str.as_str()),
        "event 1 uid"
    );
    assert_eq!(
        events[2].object_uid.as_deref(),
        Some("00000000-0000-0000-0000-000000000000"),
        "event 2 uid"
    );
    assert!(
        events[3].object_uid.is_some(),
        "event 3 (batch-Create) should have a uid"
    );

    // Hash chain integrity holds regardless of wire format.
    let mut prev = None;
    for ev in &events {
        assert!(
            verify_event(ev),
            "hash integrity failed for event id={}",
            ev.id
        );
        assert!(
            verify_chain_link(ev, prev),
            "chain link broken at event id={}",
            ev.id
        );
        prev = Some(ev);
    }

    Ok(())
}

/// CQ-05a: an unauthenticated request must still produce an audit event.
///
/// `AuditMiddleware` is wrapped outside `ensure_auth_middleware` in production
/// (`start_kms_server.rs`), specifically so it can record requests that never
/// reach a handler because auth rejected them first. `test_app_with_audit_and_auth`
/// replicates that relative wrap order with no upstream JWT/API-token/cert
/// middleware, so `ensure_auth_middleware` always returns 401.
#[tokio::test]
async fn audit_records_401_unauthenticated() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let path = temp_path("e2e_401");
    let (app, store) = test_utils::test_app_with_audit_and_auth(&path).await;
    let fut = async {
        let create_request = symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            256,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )?;
        let req = actix_test::TestRequest::post()
            .uri("/kmip/2_1")
            .set_json(to_ttlv(&create_request)?)
            .to_request();
        let res = call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "expected 401");

        Ok::<(), crate::error::KmsError>(())
    };

    Box::pin(fut).await?;

    // Deterministic drain barrier instead of a fixed sleep.
    store.flush().await;

    let file = std::fs::File::open(&path).expect("audit file not created");
    let events: Vec<cosmian_kms_access::audit::AuditEvent> =
        std::io::BufRead::lines(std::io::BufReader::new(file))
            .filter_map(|l| {
                let l = l.unwrap();
                if l.trim().is_empty() {
                    None
                } else {
                    Some(serde_json::from_str(&l).unwrap())
                }
            })
            .collect();

    assert_eq!(
        events.len(),
        1,
        "expected exactly 1 audit event, got {}",
        events.len()
    );
    assert!(
        matches!(&events[0].result, AuditResult::Failure(reason) if reason == "401 Unauthorized"),
        "expected a 401 Unauthorized failure event, got {:?}",
        events[0].result
    );
    assert_eq!(
        events[0].user, "unauthenticated",
        "unauthenticated request must be attributed to the unauthenticated user"
    );

    Ok(())
}
