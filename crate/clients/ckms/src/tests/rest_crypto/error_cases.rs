//! Integration tests for REST crypto API error cases
//!
//! Coverage:
//!   - Unknown algorithm in encrypt → 422
//!   - Unknown algorithm in sign → 422
//!   - Nonexistent key ID → 404 or 400
//!   - Wrong key type (AES key used for sign) → non-200

use cosmian_kms_cli_actions::actions::symmetric::keys::create_key::CreateKeyAction;
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_logger::log_init;
use serde_json::json;
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::{save_kms_cli_config, symmetric::create_key::create_symmetric_key},
};

use super::{base_url, test_http_client};

/// An unsupported alg/enc combination on /encrypt returns 422.
#[tokio::test]
pub(crate) async fn test_unknown_encrypt_alg_returns_422() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    let kid = create_symmetric_key(
        &conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let resp = client
        .post(format!("{base}/encrypt"))
        .json(&json!({
            "kid": kid,
            "alg": "RSA-OAEP-256",   // Phase-1 only supports "dir"
            "enc": "A256GCM",
            "data": "dGVzdA"
        }))
        .send()
        .await
        .expect("encrypt request failed");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported alg should return 422"
    );
    Ok(())
}

/// An unsupported algorithm on /sign returns 422.
#[tokio::test]
pub(crate) async fn test_unknown_sign_alg_returns_422() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    let kid = create_symmetric_key(
        &conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let resp = client
        .post(format!("{base}/sign"))
        .json(&json!({
            "kid":  kid,
            "alg":  "XYZ-UNKNOWN",
            "data": "dGVzdA"
        }))
        .send()
        .await
        .expect("sign request failed");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported alg should return 422"
    );
    Ok(())
}

/// Using a nonexistent key ID returns a 4xx error.
#[tokio::test]
pub(crate) async fn test_nonexistent_key_id() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    let resp = client
        .post(format!("{base}/encrypt"))
        .json(&json!({
            "kid": "00000000-0000-0000-0000-000000000000",
            "alg": "dir",
            "enc": "A256GCM",
            "data": "dGVzdA"
        }))
        .send()
        .await
        .expect("encrypt request failed");

    assert!(
        resp.status().is_client_error(),
        "nonexistent key should return 4xx, got {}",
        resp.status()
    );
    Ok(())
}

/// Using an AES key for a sign operation returns a non-200 response.
#[tokio::test]
pub(crate) async fn test_wrong_key_type_for_sign() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    // AES key is not valid for RSA sign operations
    let kid = create_symmetric_key(
        &conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let resp = client
        .post(format!("{base}/sign"))
        .json(&json!({
            "kid":  kid,
            "alg":  "RS256",
            "data": "dGVzdA"
        }))
        .send()
        .await
        .expect("sign (wrong key type) request failed");

    assert!(
        !resp.status().is_success(),
        "sign with wrong key type should fail, got {}",
        resp.status()
    );
    Ok(())
}
