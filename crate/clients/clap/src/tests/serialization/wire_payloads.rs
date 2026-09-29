//! Adversarial serialization tests — send malformed or oversized TTLV payloads
//! directly over HTTP and verify the server remains alive and returns HTTP 200
//! (with a TTLV error body) for every case.
//!
//! These tests cover the security hardening from the OWASP remediations:
//!   - Depth-limit bypass attempts (> `MAX_TTLV_DEPTH` = 64 nesting levels)
//!   - Truncated payloads that would normally cause a panic through underflow
//!   - Malformed JSON on the `/kmip/2_1` endpoint
//!   - Invalid type bytes / tag bytes

use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

// ---------------------------------------------------------------------------
// Helper: POST raw bytes to the binary KMIP endpoint.
//
// Returns the HTTP status code. The server is always expected to return 200;
// a non-200 (or a connection error) means the server crashed or rejected
// the request at the transport layer (rate-limiter, payload too large, etc.).
// ---------------------------------------------------------------------------
async fn raw_binary_post(port: u16, body: Vec<u8>) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/kmip"))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .expect("HTTP request must not fail (connection error)")
        .status()
}

// ---------------------------------------------------------------------------
// Helper: POST a JSON string to the JSON KMIP 2.1 endpoint.
// ---------------------------------------------------------------------------
async fn raw_json_post(port: u16, body: String) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/kmip/2_1"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .expect("HTTP request must not fail (connection error)")
        .status()
}

// ---------------------------------------------------------------------------
// Helper: build `depth` nested Structures in TTLV binary format, each
// wrapping the next, with an Integer leaf at the innermost level.
// This is the same construction used in the KMIP unit tests.
// ---------------------------------------------------------------------------
fn nested_structures_bytes(depth: usize) -> Vec<u8> {
    // --- leaf: BatchCount Integer (tag 0x42 00 0D, type 0x02, length 4, value 1, pad 4) ---
    let leaf: Vec<u8> = vec![
        0x42, 0x00, 0x0D, // tag: BatchCount
        0x02, // type: Integer
        0x00, 0x00, 0x00, 0x04, // length: 4
        0x00, 0x00, 0x00, 0x01, // value: 1
        0x00, 0x00, 0x00, 0x00, // padding
    ];

    // --- innermost structure wrapping the leaf ---
    let inner_len = u32::try_from(leaf.len()).unwrap_or(0);
    let mut inner: Vec<u8> = vec![
        0x42, 0x00, 0x7B, 0x01, // tag=RequestMessage, type=Structure
    ];
    inner.extend_from_slice(&inner_len.to_be_bytes());
    inner.extend_from_slice(&leaf);

    // --- nest `depth - 1` more wrapper structures ---
    for _ in 1..depth {
        let content_len = u32::try_from(inner.len()).unwrap_or(0);
        let mut outer = vec![0x42, 0x00, 0x7B, 0x01_u8];
        outer.extend_from_slice(&content_len.to_be_bytes());
        outer.extend_from_slice(&inner);
        inner = outer;
    }
    inner
}

// ---------------------------------------------------------------------------
// S1: Empty body — server must return 200 (not crash)
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s01_empty_body_returns_ok() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let status = raw_binary_post(ctx.server_port, vec![]).await;
    assert_eq!(
        status.as_u16(),
        200,
        "empty binary body must return HTTP 200 (server alive)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S2: Single garbage byte — server must return 200
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s02_single_garbage_byte() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let status = raw_binary_post(ctx.server_port, vec![0xDE]).await;
    assert_eq!(status.as_u16(), 200, "single garbage byte must return 200");
    Ok(())
}

// ---------------------------------------------------------------------------
// S3: All-zeros 64-byte payload
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s03_all_zeros_payload() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let status = raw_binary_post(ctx.server_port, vec![0x00; 64]).await;
    assert_eq!(status.as_u16(), 200, "all-zeros payload must return 200");
    Ok(())
}

// ---------------------------------------------------------------------------
// S4: Truncated header (7 bytes) — server must return 200
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s04_truncated_header() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let data = vec![0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00];
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(status.as_u16(), 200, "truncated header must return 200");
    Ok(())
}

// ---------------------------------------------------------------------------
// S5: Invalid type byte 0xFF in header — server must return 200
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s05_invalid_type_byte() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let data = vec![
        0x42, 0x00, 0x7B, 0xFF, // invalid type byte
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "invalid type byte must return 200 (not crash)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S6: Depth limit exceeded (66 nesting levels, limit=64) — regression for the
//     MAX_TTLV_DEPTH guard; server must return 200 and not crash
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s06_depth_exceeds_limit_no_crash() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // 66 levels puts deepest parse at depth=65, which is > MAX_TTLV_DEPTH=64
    let data = nested_structures_bytes(66);
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "depth-exceeded payload must return 200 (depth guard active)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S7: Child length > parent remaining — regression for `remaining -= item_length`
//     underflow; server must return 200 and not crash
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s07_child_exceeds_parent_length_no_crash() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // Parent Structure (tag=0x42007B) claims length=8 but contains a full 16-byte Integer child.
    //   Structure header:  42 00 7B 01 00 00 00 08
    //   Integer child:     42 00 0D 02 00 00 00 04 00 00 00 01 00 00 00 00  (16 bytes)
    let data = vec![
        // Structure: tag=RequestMessage, type=Structure, length=8 (too small)
        0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00, 0x08,
        // Integer child (16 bytes — exceeds parent's declared 8)
        0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00,
    ];
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "child-exceeds-parent payload must return 200 (underflow guard active)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S8: Payload with declared length u32::MAX — server must not try to allocate
//     4 GB and must return 200
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s08_huge_declared_length_no_oom() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // TextString declaring length=u32::MAX, only 4 actual value bytes follow.
    let mut data = vec![
        0x42, 0x00, 0x0A, // tag: AttributeName
        0x07, // type: TextString
        0xFF, 0xFF, 0xFF, 0xFF, // length: u32::MAX ≈ 4 GB claimed
    ];
    data.extend_from_slice(b"AABB"); // only 4 actual bytes
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "huge declared-length payload must return 200 (EOF error, no OOM)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S9: 1000 nested Structures (extreme depth, far above limit) — no stack overflow
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s09_extreme_nesting_no_stack_overflow() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let data = nested_structures_bytes(1000);
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "extreme nesting must return 200 (not stack-overflow)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S10: Malformed JSON to /kmip/2_1 — not valid JSON at all
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s10_malformed_json_not_crashable() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // The JSON deserialization failure should return a proper error response, not crash.
    // The /kmip/2_1 endpoint DOES return an error status when it cannot deserialize.
    let status = raw_json_post(ctx.server_port, "this is not json {{{{{{{".to_owned()).await;
    // /kmip/2_1 is a typed actix-web JSON extractor; it returns ~400 for invalid JSON.
    // What matters is the server is still alive and responds.
    assert!(
        status.as_u16() < 500,
        "malformed JSON should not cause server 5xx, got {status}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S11: Valid JSON wrapper but unknown tag — server should return 200 with error body
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s11_unknown_json_ttlv_tag() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let body = r#"{"tag":"UnknownOperationXYZZY","type":"Structure","value":[]}"#.to_owned();
    let status = raw_json_post(ctx.server_port, body).await;
    // The server should return without crashing (status < 500)
    assert!(
        status.as_u16() < 500,
        "unknown TTLV tag JSON must not cause 5xx, got {status}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// S12: 1 MB random binary payload — server must handle it gracefully (not crash)
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn s12_one_mb_random_binary() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    // Pseudo-random 1 MB body (just repeated pattern — no real entropy needed)
    #[allow(clippy::cast_possible_truncation)]
    let data: Vec<u8> = (0_u32..=1_048_575)
        .map(|i| (i.wrapping_mul(6_364_136_223_846_793_005_u64 as u32)) as u8)
        .collect();
    let status = raw_binary_post(ctx.server_port, data).await;
    assert_eq!(
        status.as_u16(),
        200,
        "1 MB random payload must return 200 (server alive)"
    );
    Ok(())
}
