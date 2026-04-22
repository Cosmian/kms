//! Integration tests for POST /v1/crypto/sign and POST /v1/crypto/verify
//!
//! Coverage:
//!   - RS256 sign/verify round-trip (RSA-2048)
//!   - ES256 sign/verify round-trip (EC P-256)
//!   - Verification fails when the signing input is tampered

use cosmian_logger::log_init;
use serde_json::{Value, json};
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{
        elliptic_curve::create_key_pair::create_ec_key_pair,
        rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
        save_kms_cli_config,
    },
};

use super::{base_url, test_http_client};

/// RS256 sign/verify round-trip via the REST crypto API.
#[tokio::test]
pub(crate) async fn test_rs256_round_trip() -> CosmianResult<()> {
    log_init(None);
    sign_verify_round_trip("RS256", |conf_path| {
        Box::pin(async move {
            create_rsa_key_pair(
                conf_path,
                &RsaKeyPairOptions {
                    number_of_bits: Some(2048),
                    ..Default::default()
                },
            )
        })
    })
    .await
}

/// ES256 sign/verify round-trip via the REST crypto API.
#[tokio::test]
pub(crate) async fn test_es256_round_trip() -> CosmianResult<()> {
    log_init(None);
    sign_verify_round_trip("ES256", |conf_path| {
        Box::pin(async move { create_ec_key_pair(conf_path, "nist-p256", &[], false) })
    })
    .await
}

/// Generic sign/verify round-trip helper.
///
/// `create_pair_fn` returns `(private_key_id, public_key_id)`.
async fn sign_verify_round_trip<F, Fut>(alg: &str, create_pair_fn: F) -> CosmianResult<()>
where
    F: FnOnce(&str) -> Fut,
    Fut: std::future::Future<Output = CosmianResult<(String, String)>>,
{
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    let (private_key_id, public_key_id) = create_pair_fn(&conf_path).await?;

    let data_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"data to sign",
    );

    // Sign
    let sign_resp: Value = client
        .post(format!("{base}/sign"))
        .json(&json!({
            "kid": private_key_id,
            "alg": alg,
            "data": data_b64
        }))
        .send()
        .await
        .expect("sign request failed")
        .json()
        .await
        .expect("sign response not JSON");

    let protected = sign_resp["protected"]
        .as_str()
        .expect("sign response missing 'protected'");
    let signature = sign_resp["signature"]
        .as_str()
        .expect("sign response missing 'signature'");

    // Verify (valid)
    let verify_resp: Value = client
        .post(format!("{base}/verify"))
        .json(&json!({
            "protected": protected,
            "data":      data_b64,
            "signature": signature
        }))
        .send()
        .await
        .expect("verify request failed")
        .json()
        .await
        .expect("verify response not JSON");

    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "verify should return valid=true; response: {verify_resp}"
    );

    // Verify the public key matches
    assert_eq!(
        verify_resp["kid"].as_str().expect("missing kid in verify response"),
        public_key_id,
        "verify kid should be the public key"
    );

    // Verify with tampered data → invalid
    let tampered_data_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"tampered data",
    );
    let tampered_resp = client
        .post(format!("{base}/verify"))
        .json(&json!({
            "protected": protected,
            "data":      tampered_data_b64,
            "signature": signature
        }))
        .send()
        .await
        .expect("verify (tampered) request failed");

    // A tampered signing input must either fail or return valid=false.
    if tampered_resp.status().is_success() {
        let tampered_json: Value = tampered_resp
            .json()
            .await
            .expect("tampered verify response not JSON");
        assert_eq!(
            tampered_json["valid"].as_bool(),
            Some(false),
            "tampered data should yield valid=false; response: {tampered_json}"
        );
    }

    Ok(())
}
