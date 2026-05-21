//! Data-driven JOSE test runner that loads JSON vector files from
//! `test_data/vectors/jose/` and exercises the REST crypto endpoints.
//!
//! Each JSON file describes one test scenario with type, algorithm, key spec,
//! and expected behavior. The runner provisions keys via KMIP, calls the
//! appropriate endpoint, and asserts the result.

use std::{fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::{CreateKeyPairResponse, CreateResponse},
    kmip_types::RecommendedCurve,
    requests::{
        create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

/// Root directory for JOSE test vectors (relative to workspace root).
fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent of server crate")
        .parent()
        .expect("workspace root")
        .join("test_data/vectors/jose")
}

/// Load and parse a single JSON vector file.
fn load_vector(filename: &str) -> Value {
    let path = vectors_dir().join(filename);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read vector file {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse vector file {}: {e}", path.display()))
}

/// Resolve the plaintext for a request: either literal `data_plaintext` or
/// generated via `data_plaintext_generator`.
fn resolve_plaintext(request: &Value) -> Vec<u8> {
    if let Some(pt) = request.get("data_plaintext") {
        return pt.as_str().unwrap_or("").as_bytes().to_vec();
    }
    if let Some(generator) = request.get("data_plaintext_generator") {
        if generator.as_str() == Some("repeat_pattern") {
            let pattern = request["pattern"].as_str().unwrap_or("A");
            let target_bytes = usize::try_from(request["repeat_bytes"].as_u64().unwrap_or(256))
                .expect("repeat_bytes fits usize");
            return pattern
                .as_bytes()
                .iter()
                .cycle()
                .take(target_bytes)
                .copied()
                .collect();
        }
    }
    b"default test payload".to_vec()
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAC Known-Answer Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test: `rfc7515_a1_hs256_kat.json` — HS256 HMAC known-answer from RFC 7515 §A.1
#[tokio::test]
async fn test_vector_rfc7515_a1_hs256_kat() -> KResult<()> {
    log_init(None);
    let v = load_vector("rfc7515_a1_hs256_kat.json");
    let app = test_utils::test_app(None, None).await;

    // Import the exact key from the vector
    let key_b64 = v["key"]["k"].as_str().expect("key.k missing");
    let key_bytes = URL_SAFE_NO_PAD
        .decode(key_b64)
        .expect("key is valid base64url");
    let kid = super::common::import_hmac_key(&app, key_bytes).await?;

    // The "data" field in the request is already base64url-encoded signing input
    let data_b64 = v["request"]["data"].as_str().expect("request.data missing");

    // Compute MAC
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;

    let got_mac = compute_resp["mac"].as_str().expect("missing mac field");
    let expected_mac = v["expected"]["mac"].as_str().expect("expected.mac missing");
    assert_eq!(
        got_mac, expected_mac,
        "Vector rfc7515_a1_hs256_kat: MAC mismatch"
    );

    // Verify round-trip
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": got_mac}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(verify_resp["valid"].as_bool(), Some(true));

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAC Round-Trip Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Generic MAC round-trip test: import/generate key → compute → verify.
async fn run_mac_round_trip(filename: &str) -> KResult<()> {
    let v = load_vector(filename);
    let app = test_utils::test_app(None, None).await;

    let alg = v["algorithm"].as_str().expect("algorithm missing");
    let bits =
        usize::try_from(v["key_spec"]["bits"].as_u64().unwrap_or(256)).expect("bits fits usize");
    let key_bytes = vec![0x42_u8; bits / 8];
    let kid = super::common::import_hmac_key(&app, key_bytes).await?;

    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Compute
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"].as_str().expect("missing mac");

    // Verify
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": alg, "data": data_b64, "mac": mac_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "Vector {filename}: MAC verify must return valid=true"
    );

    Ok(())
}

#[tokio::test]
async fn test_vector_rfc7518_hs384() -> KResult<()> {
    log_init(None);
    run_mac_round_trip("rfc7518_hs384.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_hs512() -> KResult<()> {
    log_init(None);
    run_mac_round_trip("rfc7518_hs512.json").await
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAC Wrong-Key Rejection
// ═══════════════════════════════════════════════════════════════════════════════

/// Test: `rfc7515_hs256_wrong_key.json` — MAC from key A fails verify with key B
#[tokio::test]
async fn test_vector_rfc7515_hs256_wrong_key() -> KResult<()> {
    log_init(None);
    let v = load_vector("rfc7515_hs256_wrong_key.json");
    let app = test_utils::test_app(None, None).await;

    let bits =
        usize::try_from(v["key_spec"]["bits"].as_u64().unwrap_or(256)).expect("bits fits usize");

    // Key A
    let key_a = vec![0xAA_u8; bits / 8];
    let kid_a = super::common::import_hmac_key(&app, key_a).await?;

    // Key B (different)
    let key_b = vec![0xBB_u8; bits / 8];
    let kid_b = super::common::import_hmac_key(&app, key_b).await?;

    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Compute with key A
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_a, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"].as_str().expect("missing mac");

    // Verify with key B → must fail
    let req = actix_web::test::TestRequest::post()
        .uri("/v1/crypto/mac")
        .set_json(&json!({"kid": kid_b, "alg": "HS256", "data": data_b64, "mac": mac_b64}))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    if resp.status() == actix_web::http::StatusCode::OK {
        let body = actix_web::test::read_body(resp).await;
        let parsed: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            parsed["valid"].as_bool(),
            Some(false),
            "Vector rfc7515_hs256_wrong_key: MAC from key A must fail verify with key B"
        );
    }
    // Non-200 is also acceptable (server rejected outright)

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sign/Verify Round-Trip Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Generic sign/verify round-trip: create key pair → sign → verify.
async fn run_sign_verify_round_trip(filename: &str) -> KResult<()> {
    let v = load_vector(filename);
    let app = test_utils::test_app(None, None).await;

    let alg = v["algorithm"].as_str().expect("algorithm missing");
    let key_spec = &v["key_spec"];
    let key_type = key_spec["type"].as_str().unwrap_or("RSA");

    let (private_kid, public_kid) = match key_type {
        "RSA" => {
            let bits = usize::try_from(key_spec["bits"].as_u64().unwrap_or(2048))
                .expect("bits fits usize");
            let kp_req = create_rsa_key_pair_request(
                VENDOR_ID_COSMIAN,
                None,
                EMPTY_TAGS,
                bits,
                false,
                None,
            )?;
            let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
            (
                kp_resp.private_key_unique_identifier.to_string(),
                kp_resp.public_key_unique_identifier.to_string(),
            )
        }
        "EC" => {
            let curve = match key_spec["curve"].as_str().unwrap_or("P-256") {
                "P-256" => RecommendedCurve::P256,
                "P-384" => RecommendedCurve::P384,
                "P-521" => RecommendedCurve::P521,
                c => panic!("unsupported curve: {c}"),
            };
            let kp_req = create_ec_key_pair_request(
                VENDOR_ID_COSMIAN,
                None,
                EMPTY_TAGS,
                curve,
                false,
                None,
            )?;
            let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
            (
                kp_resp.private_key_unique_identifier.to_string(),
                kp_resp.public_key_unique_identifier.to_string(),
            )
        }
        t => panic!("unsupported key type in vector: {t}"),
    };

    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Sign
    let sign_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": private_kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/sign",
    )
    .await?;

    let protected = sign_resp["protected"].as_str().expect("missing protected");
    let signature = sign_resp["signature"].as_str().expect("missing signature");

    // Verify
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"protected": protected, "data": data_b64, "signature": signature}),
        "/v1/crypto/verify",
    )
    .await?;

    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "Vector {filename}: sign/verify round-trip must succeed"
    );
    assert_eq!(
        verify_resp["kid"].as_str().expect("missing kid"),
        public_kid,
        "Vector {filename}: verify kid must match public key"
    );

    Ok(())
}

#[tokio::test]
async fn test_vector_rfc7515_a2_rs256() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7515_a2_rs256.json").await
}

#[tokio::test]
async fn test_vector_rfc7515_a3_es256() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7515_a3_es256.json").await
}

#[tokio::test]
async fn test_vector_rfc7515_a4_es512() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7515_a4_es512.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_rs384() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_rs384.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_rs512() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_rs512.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_ps256() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_ps256.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_ps384() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_ps384.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_ps512() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_ps512.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_es384() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7518_es384.json").await
}

#[tokio::test]
async fn test_vector_rfc7520_s4_1_rs256() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7520_s4_1_rs256.json").await
}

#[tokio::test]
async fn test_vector_rfc7520_s4_2_ps384() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7520_s4_2_ps384.json").await
}

#[tokio::test]
async fn test_vector_rfc7520_s4_3_es512() -> KResult<()> {
    log_init(None);
    run_sign_verify_round_trip("rfc7520_s4_3_es512.json").await
}

// ═══════════════════════════════════════════════════════════════════════════════
// RFC 7520 §4.4 — HMAC-SHA2 Cookbook (HS256)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_vector_rfc7520_s4_4_hs256() -> KResult<()> {
    log_init(None);
    let v = load_vector("rfc7520_s4_4_hs256.json");
    let app = test_utils::test_app(None, None).await;

    // Import the key from the vector
    let key_b64 = v["key"]["k"].as_str().expect("key.k missing");
    let key_bytes = URL_SAFE_NO_PAD
        .decode(key_b64)
        .expect("key is valid base64url");
    let kid = super::common::import_hmac_key(&app, key_bytes).await?;

    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Compute
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"].as_str().expect("missing mac");

    // Verify
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": mac_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "Vector rfc7520_s4_4_hs256: MAC verify must return valid=true"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypt/Decrypt Round-Trip Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Generic encrypt/decrypt round-trip: create AES key → encrypt → decrypt → assert match.
async fn run_encrypt_decrypt_round_trip(filename: &str) -> KResult<()> {
    let v = load_vector(filename);
    let app = test_utils::test_app(None, None).await;

    let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
    let bits =
        usize::try_from(v["key_spec"]["bits"].as_u64().unwrap_or(256)).expect("bits fits usize");

    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        bits,
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(&app, create_req).await?;
    let kid = cr.unique_identifier.to_string();

    let plaintext = resolve_plaintext(&v["request"]);
    let plaintext_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Encrypt
    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(enc_resp.get("ciphertext").is_some(), "missing ciphertext");
    assert!(enc_resp.get("iv").is_some(), "missing iv");
    assert!(enc_resp.get("tag").is_some(), "missing tag");

    // Decrypt
    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64 decode");
    assert_eq!(
        recovered, plaintext,
        "Vector {filename}: decrypt must yield original plaintext"
    );

    Ok(())
}

#[tokio::test]
async fn test_vector_rfc7518_a128gcm_dir() -> KResult<()> {
    log_init(None);
    run_encrypt_decrypt_round_trip("rfc7518_a128gcm_dir.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_a192gcm_dir() -> KResult<()> {
    log_init(None);
    run_encrypt_decrypt_round_trip("rfc7518_a192gcm_dir.json").await
}

#[tokio::test]
async fn test_vector_rfc7518_a256gcm_dir() -> KResult<()> {
    log_init(None);
    run_encrypt_decrypt_round_trip("rfc7518_a256gcm_dir.json").await
}

#[tokio::test]
async fn test_vector_rfc7516_empty_plaintext() -> KResult<()> {
    log_init(None);
    run_encrypt_decrypt_round_trip("rfc7516_empty_plaintext.json").await
}

#[tokio::test]
async fn test_vector_rfc7516_large_plaintext() -> KResult<()> {
    log_init(None);
    run_encrypt_decrypt_round_trip("rfc7516_large_plaintext.json").await
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypt/Decrypt Tamper Rejection Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Generic tamper-rejection test: encrypt → tamper one field → decrypt must fail.
async fn run_tamper_reject(filename: &str) -> KResult<()> {
    let v = load_vector(filename);
    let app = test_utils::test_app(None, None).await;

    let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
    let bits =
        usize::try_from(v["key_spec"]["bits"].as_u64().unwrap_or(256)).expect("bits fits usize");

    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        bits,
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(&app, create_req).await?;
    let kid = cr.unique_identifier.to_string();

    let plaintext = resolve_plaintext(&v["request"]);
    let plaintext_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Encrypt
    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Determine which field to tamper
    let tamper_field = v["tamper"]["field"].as_str().expect("tamper.field missing");

    let mut decrypt_payload = json!({
        "protected":  enc_resp["protected"],
        "iv":         enc_resp["iv"],
        "ciphertext": enc_resp["ciphertext"],
        "tag":        enc_resp["tag"]
    });

    match tamper_field {
        "protected" => {
            // Flip one character in the protected header
            let orig = enc_resp["protected"].as_str().unwrap();
            let tampered = orig
                .strip_prefix('e')
                .map_or_else(|| format!("e{}", &orig[1..]), |rest| format!("f{rest}"));
            decrypt_payload["protected"] = Value::String(tampered);
        }
        "tag" => {
            let mut tag_bytes = URL_SAFE_NO_PAD
                .decode(enc_resp["tag"].as_str().unwrap())
                .unwrap();
            tag_bytes[0] ^= 0xFF;
            decrypt_payload["tag"] = Value::String(URL_SAFE_NO_PAD.encode(&tag_bytes));
        }
        "ciphertext" => {
            let mut ct_bytes = URL_SAFE_NO_PAD
                .decode(enc_resp["ciphertext"].as_str().unwrap())
                .unwrap();
            ct_bytes[0] ^= 0xFF;
            decrypt_payload["ciphertext"] = Value::String(URL_SAFE_NO_PAD.encode(&ct_bytes));
        }
        f => panic!("unsupported tamper field: {f}"),
    }

    // Decrypt with tampered data must fail
    let req = actix_web::test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&decrypt_payload)
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        actix_web::http::StatusCode::OK,
        "Vector {filename}: tampered {tamper_field} must cause decryption failure"
    );

    Ok(())
}

#[tokio::test]
async fn test_vector_rfc7516_aad_binding_tamper() -> KResult<()> {
    log_init(None);
    run_tamper_reject("rfc7516_aad_binding_tamper.json").await
}

#[tokio::test]
async fn test_vector_rfc7516_tampered_tag() -> KResult<()> {
    log_init(None);
    run_tamper_reject("rfc7516_tampered_tag.json").await
}

#[tokio::test]
async fn test_vector_rfc7516_tampered_ciphertext() -> KResult<()> {
    log_init(None);
    run_tamper_reject("rfc7516_tampered_ciphertext.json").await
}
