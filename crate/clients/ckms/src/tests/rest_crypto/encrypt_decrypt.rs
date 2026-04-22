//! Integration tests for POST /v1/crypto/encrypt and POST /v1/crypto/decrypt
//!
//! Coverage:
//!   - AES-128-GCM round-trip (dir + A128GCM)
//!   - AES-256-GCM round-trip (dir + A256GCM)
//!   - AAD binding: decrypt succeeds with correct AAD, fails when AAD is modified

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

/// AES-128-GCM encrypt/decrypt round-trip via the REST crypto API.
#[tokio::test]
pub(crate) async fn test_aes128gcm_round_trip() -> CosmianResult<()> {
    log_init(None);
    aes_gcm_round_trip(128, "A128GCM").await
}

/// AES-256-GCM encrypt/decrypt round-trip via the REST crypto API.
#[tokio::test]
pub(crate) async fn test_aes256gcm_round_trip() -> CosmianResult<()> {
    log_init(None);
    aes_gcm_round_trip(256, "A256GCM").await
}

async fn aes_gcm_round_trip(bits: usize, enc_alg: &str) -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (conf_path, _) = save_kms_cli_config(ctx);
    let port = ctx.server_port;
    let client = test_http_client();
    let base = base_url(port);

    // Create AES key
    let kid = create_symmetric_key(
        &conf_path,
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(bits),
            ..Default::default()
        },
    )?;

    let plaintext_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"Hello, REST crypto API!",
    );

    // Encrypt
    let enc_resp: Value = client
        .post(format!("{base}/encrypt"))
        .json(&json!({
            "kid": kid,
            "alg": "dir",
            "enc": enc_alg,
            "data": plaintext_b64
        }))
        .send()
        .await
        .expect("encrypt request failed")
        .json()
        .await
        .expect("encrypt response not JSON");

    assert!(enc_resp.get("ciphertext").is_some(), "missing ciphertext");
    assert!(enc_resp.get("iv").is_some(), "missing iv");
    assert!(enc_resp.get("tag").is_some(), "missing tag");

    // Decrypt
    let dec_resp: Value = client
        .post(format!("{base}/decrypt"))
        .json(&json!({
            "protected": enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":         enc_resp["tag"]
        }))
        .send()
        .await
        .expect("decrypt request failed")
        .json()
        .await
        .expect("decrypt response not JSON");

    let recovered_b64 = dec_resp["data"]
        .as_str()
        .expect("decrypt response missing 'data'");
    let recovered = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        recovered_b64,
    )
    .expect("base64 decode failed");

    assert_eq!(recovered, b"Hello, REST crypto API!");
    Ok(())
}

/// Encrypt with AAD; decrypt must succeed with the same AAD
/// and must fail (non-200) when AAD is changed.
#[tokio::test]
pub(crate) async fn test_aad_binding() -> CosmianResult<()> {
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

    let plaintext_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"secret payload",
    );
    let aad_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"associated-data",
    );
    let wrong_aad_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"tampered-aad",
    );

    // Encrypt with AAD
    let enc_resp: Value = client
        .post(format!("{base}/encrypt"))
        .json(&json!({
            "kid": kid,
            "alg": "dir",
            "enc": "A256GCM",
            "data": plaintext_b64,
            "aad": aad_b64
        }))
        .send()
        .await
        .expect("encrypt request failed")
        .json()
        .await
        .expect("encrypt response not JSON");

    // Correct AAD → success
    let dec_ok = client
        .post(format!("{base}/decrypt"))
        .json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
            "aad":        aad_b64
        }))
        .send()
        .await
        .expect("decrypt (correct AAD) request failed");
    assert!(
        dec_ok.status().is_success(),
        "decrypt with correct AAD should succeed, got {}",
        dec_ok.status()
    );

    // Wrong AAD → failure (GCM authentication tag mismatch)
    let dec_bad = client
        .post(format!("{base}/decrypt"))
        .json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
            "aad":        wrong_aad_b64
        }))
        .send()
        .await
        .expect("decrypt (wrong AAD) request failed");
    assert!(
        !dec_bad.status().is_success(),
        "decrypt with wrong AAD should fail, got {}",
        dec_bad.status()
    );

    Ok(())
}
