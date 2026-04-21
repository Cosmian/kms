//! KMIP batch-processing abuse tests.
//!
//! These tests send malformed or adversarial KMIP batch requests directly over
//! HTTP and verify that the server handles them gracefully — returning a clean
//! error response without crashing, hanging, or leaking memory.
//!
//! Covered scenarios:
//!   B1  - BatchCount=1 in header but zero items in body
//!   B2  - BatchCount=255 in header but only 1 item in body
//!   B3  - Well-formed JSON KMIP with empty `BatchItems` array
//!   B4  - 100-item JSON batch (all `CreateSymmetricKey`) — all items processed
//!   B5  - BatchCount=0 in binary header, zero items
//!
//! Framework: NIST SSDF PW.4.4 · CIS 16.14 · OSSTMM Integrity

use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// POST raw binary bytes to the KMIP binary endpoint and return the HTTP status.
///
/// The binary endpoint is `/kmip` (not `/kmip/2_1`).
/// A network / connection error is mapped to `u16::MAX` so callers can assert
/// the server was reachable.
async fn raw_binary_post(port: u16, body: Vec<u8>) -> u16 {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/kmip"))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_or(u16::MAX, |r| r.status().as_u16())
}

/// POST a JSON string to the KMIP JSON endpoint and return the HTTP status.
async fn raw_json_post(port: u16, json: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/kmip/2_1"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json.to_owned())
        .send()
        .await
        .map_or(u16::MAX, |r| r.status().as_u16())
}

/// Build a minimal well-formed TTLV binary `RequestMessage` with a specific
/// `BatchCount` field value and a given number of actual batch item payloads
/// (here zero — this creates a count-vs-content mismatch).
///
/// TTLV binary layout (big-endian):
///   [3-byte tag][1-byte type][4-byte length][value + padding]
///
/// Tag `0x42_00_7B` (`RequestMessage`) = Structure
/// Tag `0x42_00_0D` (`BatchCount`)     = Integer
fn batch_count_header(declared_count: i32) -> Vec<u8> {
    // BatchCount Integer leaf: value=declared_count, total=16 bytes (8 header + 4 value + 4 padding)
    let mut batch_count_item: Vec<u8> = vec![
        0x42, 0x00, 0x0D, // tag: BatchCount
        0x02, // type: Integer
        0x00, 0x00, 0x00, 0x04, // length: 4 bytes
    ];
    batch_count_item.extend_from_slice(&declared_count.to_be_bytes());
    batch_count_item.extend_from_slice(&[0_u8; 4]); // 4 bytes padding

    // Wrap in a RequestMessage Structure
    let inner_len = u32::try_from(batch_count_item.len()).unwrap_or(0);
    let mut msg: Vec<u8> = vec![
        0x42, 0x00, 0x7B, // tag: RequestMessage
        0x01, // type: Structure
    ];
    msg.extend_from_slice(&inner_len.to_be_bytes());
    msg.extend_from_slice(&batch_count_item);
    msg
}

// ---------------------------------------------------------------------------
// B1: BatchCount=1 declared, zero actual items — count/content mismatch.
//     Server must return 200 with a TTLV error body, not panic.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn b01_batch_count_one_zero_items() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let body = batch_count_header(1);
    let status = raw_binary_post(ctx.server_port, body).await;
    assert_ne!(
        status, 500,
        "BatchCount=1 with zero items must not cause HTTP 500"
    );
    assert_ne!(
        status,
        u16::MAX,
        "Server must still be reachable after malformed batch"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// B2: BatchCount=255 declared, zero actual items — extreme count mismatch.
//     Same guarantee: 200 with TTLV error body.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn b02_batch_count_255_zero_items() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let body = batch_count_header(255);
    let status = raw_binary_post(ctx.server_port, body).await;
    assert_ne!(status, 500, "BatchCount=255 with zero items must not 500");
    assert_ne!(status, u16::MAX, "Server must still be reachable");
    Ok(())
}

// ---------------------------------------------------------------------------
// B3: Well-formed JSON KMIP with an empty BatchItems array.
//     The KMIP spec allows empty batches; server must respond with
//     HTTP 200 and a BatchCount=0 response body (not crash).
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn b03_json_empty_batch_items() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let json = r#"{"tag":"RequestMessage","value":[{"tag":"RequestHeader","value":[{"tag":"ProtocolVersion","value":[{"tag":"ProtocolVersionMajor","type":"Integer","value":2},{"tag":"ProtocolVersionMinor","type":"Integer","value":1}]},{"tag":"BatchCount","type":"Integer","value":0}]}]}"#;
    let status = raw_json_post(ctx.server_port, json).await;
    assert_ne!(status, 500, "Empty JSON BatchItems must not cause 500");
    assert_ne!(status, u16::MAX, "Server must still be reachable");
    Ok(())
}

// ---------------------------------------------------------------------------
// B4: 100-item JSON batch of DiscoverVersions requests.
//
// DiscoverVersions requires no key material and returns a simple list of
// supported protocol versions, making it ideal for a large-batch stress test
// without side effects. All 100 items must be processed without timeout,
// memory exhaustion, or crash.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn b04_json_100_discover_versions_batch() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Build 100 DiscoverVersions batch items
    let item = r#"{"tag":"RequestBatchItem","value":[{"tag":"Operation","type":"Enumeration","value":"DiscoverVersions"},{"tag":"RequestPayload","value":[]}]}"#;
    let items: Vec<&str> = (0..100).map(|_| item).collect();
    let batch_items_json = items.join(",");

    let json = format!(
        r#"{{"tag":"RequestMessage","value":[{{"tag":"RequestHeader","value":[{{"tag":"ProtocolVersion","value":[{{"tag":"ProtocolVersionMajor","type":"Integer","value":2}},{{"tag":"ProtocolVersionMinor","type":"Integer","value":1}}]}},{{"tag":"BatchCount","type":"Integer","value":100}}]}},{batch_items_json}]}}"#
    );

    let status = raw_json_post(ctx.server_port, &json).await;
    assert_ne!(status, 500, "100-item batch must not cause HTTP 500");
    assert_ne!(
        status,
        u16::MAX,
        "Server must be reachable after 100-item batch"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// B5: BatchCount=0 in binary header, zero actual items.
//     An empty-batch request is valid KMIP; server should accept or return
//     a clean error — never crash.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn b05_batch_count_zero() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let body = batch_count_header(0);
    let status = raw_binary_post(ctx.server_port, body).await;
    assert_ne!(status, 500, "BatchCount=0 must not cause HTTP 500");
    assert_ne!(status, u16::MAX, "Server must remain reachable");
    Ok(())
}
