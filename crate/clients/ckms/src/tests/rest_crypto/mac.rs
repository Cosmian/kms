//! Integration tests for POST /v1/crypto/mac
//!
//! Coverage:
//!   - HS256 MAC compute
//!   - HS256 MAC verify (correct MAC → valid=true)
//!   - HS256 MAC verify (wrong MAC → valid=false or non-200)

use cosmian_kms_cli_actions::actions::symmetric::keys::create_key::CreateKeyAction;
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_logger::log_init;
use serde_json::{Value, json};
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{save_kms_cli_config, symmetric::create_key::create_symmetric_key},
};

use super::{base_url, test_http_client};

/// HS256 MAC compute + verify round-trip.
#[tokio::test]
pub(crate) async fn test_hs256_compute_verify() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    // Create an HMAC-compatible symmetric key (SHA3-256 is used like the existing
    // mac.rs test; the MAC operation accepts any symmetric key bytes for HMAC-SHA256).
    let kid = create_symmetric_key(
        &conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let data_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"message to authenticate",
    );

    // Compute MAC
    let compute_resp: Value = client
        .post(format!("{base}/mac"))
        .json(&json!({
            "kid":  kid,
            "alg":  "HS256",
            "data": data_b64
        }))
        .send()
        .await
        .expect("mac compute request failed")
        .json()
        .await
        .expect("mac compute response not JSON");

    let mac_b64 = compute_resp["mac"]
        .as_str()
        .expect("mac compute response missing 'mac'");

    // Verify MAC (correct) → valid=true
    let verify_resp: Value = client
        .post(format!("{base}/mac"))
        .json(&json!({
            "kid":  kid,
            "alg":  "HS256",
            "data": data_b64,
            "mac":  mac_b64
        }))
        .send()
        .await
        .expect("mac verify request failed")
        .json()
        .await
        .expect("mac verify response not JSON");

    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "MAC verify with correct mac should return valid=true; response: {verify_resp}"
    );

    // Verify MAC (wrong) → valid=false or non-200
    let wrong_mac_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &[0u8; 32],
    );
    let bad_verify_resp = client
        .post(format!("{base}/mac"))
        .json(&json!({
            "kid":  kid,
            "alg":  "HS256",
            "data": data_b64,
            "mac":  wrong_mac_b64
        }))
        .send()
        .await
        .expect("mac verify (wrong mac) request failed");

    if bad_verify_resp.status().is_success() {
        let bad_json: Value = bad_verify_resp
            .json()
            .await
            .expect("mac verify (wrong mac) response not JSON");
        assert_eq!(
            bad_json["valid"].as_bool(),
            Some(false),
            "wrong MAC should yield valid=false; response: {bad_json}"
        );
    }
    // A non-2xx status is also acceptable (server-side MAC mismatch error).

    Ok(())
}
