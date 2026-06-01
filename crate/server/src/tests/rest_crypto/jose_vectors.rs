//! Data-driven JOSE test runner that loads JSON vector files from
//! `test_data/vectors/jose/` and exercises the REST crypto endpoints.
//!
//! The runner auto-discovers all `.json` files in the vectors directory,
//! provisions keys via `POST /v1/crypto/keys` (dogfooding the new endpoint),
//! dispatches each vector by its `type` field, and cleans up via
//! `DELETE /v1/crypto/keys/{kid}`.

use std::{fs, path::PathBuf};

use actix_http::Request;
use actix_web::{
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test as actix_test,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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

/// Discover all `.json` vector files in the vectors directory.
fn discover_vectors() -> Vec<PathBuf> {
    let dir = vectors_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read vectors dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    files
}

/// Load and parse a single JSON vector file.
fn load_vector(path: &PathBuf) -> Value {
    let content = fs::read_to_string(path)
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
// Key provisioning via POST /v1/crypto/keys
// ═══════════════════════════════════════════════════════════════════════════════

/// Provision a key using `POST /v1/crypto/keys` and return `(kid, kid_public)`.
///
/// Both key generation (no material) and key import (material present via `k` or `d`)
/// are handled by the REST endpoint.
async fn provision_key<S, B>(app: &S, key: &Value) -> KResult<(String, Option<String>)>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    // All key requests (generate or import) go through POST /v1/crypto/keys
    let resp: Value = test_utils::post_json_with_uri(app, key, "/v1/crypto/keys").await?;
    let kid = resp["kid"]
        .as_str()
        .expect("POST /v1/crypto/keys response missing 'kid'")
        .to_owned();
    let kid_public = resp["kid_public"].as_str().map(ToOwned::to_owned);
    Ok((kid, kid_public))
}

/// Delete a key via `DELETE /v1/crypto/keys/{kid}`.
async fn delete_key<S, B>(app: &S, kid: &str)
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/v1/crypto/keys/{kid}"))
        .to_request();
    let resp = actix_test::call_service(app, req).await;
    assert!(
        resp.status() == StatusCode::NO_CONTENT || resp.status() == StatusCode::OK,
        "DELETE /v1/crypto/keys/{kid} failed with status {}",
        resp.status()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vector type dispatch
// ═══════════════════════════════════════════════════════════════════════════════

/// Run a single vector against the test app.
async fn run_vector<S, B>(app: &S, path: &PathBuf) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let v = load_vector(path);
    let filename = path.file_name().unwrap().to_string_lossy();
    let vector_type = v["type"]
        .as_str()
        .unwrap_or_else(|| panic!("Vector {filename}: missing 'type' field"));

    match vector_type {
        "mac_kat" => run_mac_kat(app, &v, &filename).await,
        "mac_round_trip" => run_mac_round_trip(app, &v, &filename).await,
        "mac_wrong_key_reject" => run_mac_wrong_key_reject(app, &v, &filename).await,
        "sign_verify_round_trip" => run_sign_verify_round_trip(app, &v, &filename).await,
        "encrypt_decrypt_round_trip" => run_encrypt_decrypt_round_trip(app, &v, &filename).await,
        "encrypt_decrypt_tamper_reject" => {
            run_encrypt_decrypt_tamper_reject(app, &v, &filename).await
        }
        "unwrap_key_round_trip" => run_unwrap_key_round_trip(app, &v, &filename).await,
        "key_lifecycle" => run_key_lifecycle(app, &v, &filename).await,
        "expect_error" => run_expect_error(app, &v, &filename).await,
        unknown => panic!("Vector {filename}: unknown type '{unknown}'"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAC tests
// ═══════════════════════════════════════════════════════════════════════════════

async fn run_mac_kat<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (kid, _) = provision_key(app, key).await?;

    let alg = v["algorithm"].as_str().expect("algorithm missing");

    // Support two KAT formats:
    //  1) request.data (already base64url-encoded signing input)
    //  2) request.data_plaintext (plain UTF-8 text, must be encoded)
    let data_b64 = v["request"]["data"].as_str().map_or_else(
        || {
            let plaintext = resolve_plaintext(&v["request"]);
            URL_SAFE_NO_PAD.encode(&plaintext)
        },
        str::to_owned,
    );

    // Compute MAC
    let compute_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;

    let got_mac = compute_resp["mac"]
        .as_str()
        .expect("missing mac in response");

    // Support two expected-value formats:
    //  1) expected.mac
    //  2) rfc_expected_signature (RFC 7520 style)
    let expected_mac = v["expected"]["mac"]
        .as_str()
        .or_else(|| v["rfc_expected_signature"].as_str())
        .expect("expected.mac or rfc_expected_signature missing");
    assert_eq!(got_mac, expected_mac, "Vector {filename}: MAC mismatch");

    // Also verify round-trip
    let verify_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": alg, "data": data_b64, "mac": got_mac}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "Vector {filename}: KAT MAC verify must succeed"
    );

    delete_key(app, &kid).await;
    Ok(())
}

async fn run_mac_round_trip<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (kid, _) = provision_key(app, key).await?;

    let alg = v["algorithm"].as_str().expect("algorithm missing");
    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Compute
    let compute_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"]
        .as_str()
        .expect("missing mac in response");

    // Verify
    let verify_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": alg, "data": data_b64, "mac": mac_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "Vector {filename}: MAC verify must return valid=true"
    );

    delete_key(app, &kid).await;
    Ok(())
}

async fn run_mac_wrong_key_reject<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let alg = v["algorithm"].as_str().expect("algorithm missing");

    // Create two keys of the same type
    let (kid_a, _) = provision_key(app, key).await?;
    let (kid_b, _) = provision_key(app, key).await?;

    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Compute with key A
    let compute_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid_a, "alg": alg, "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"]
        .as_str()
        .expect("missing mac in response");

    // Verify with key B → must fail
    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/mac")
        .set_json(&json!({"kid": kid_b, "alg": alg, "data": data_b64, "mac": mac_b64}))
        .to_request();
    let resp = actix_test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = actix_test::read_body(resp).await;
        let parsed: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            parsed["valid"].as_bool(),
            Some(false),
            "Vector {filename}: MAC from key A must fail verify with key B"
        );
    }
    // Non-200 is also acceptable (server rejected outright)

    delete_key(app, &kid_a).await;
    delete_key(app, &kid_b).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sign/Verify tests
// ═══════════════════════════════════════════════════════════════════════════════

async fn run_sign_verify_round_trip<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (private_kid, kid_public) = provision_key(app, key).await?;
    let public_kid = kid_public.expect("sign_verify vectors need asymmetric key (kid_public)");

    let alg = v["algorithm"].as_str().expect("algorithm missing");
    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Sign
    let sign_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": private_kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/sign",
    )
    .await?;

    let protected = sign_resp["protected"].as_str().expect("missing protected");
    let signature = sign_resp["signature"].as_str().expect("missing signature");

    // Verify
    let verify_resp: Value = test_utils::post_json_with_uri(
        app,
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

    delete_key(app, &private_kid).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypt/Decrypt tests
// ═══════════════════════════════════════════════════════════════════════════════

async fn run_encrypt_decrypt_round_trip<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (kid, kid_public) = provision_key(app, key).await?;

    let alg = v["algorithm"].as_str().unwrap_or("dir");
    let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
    let plaintext = resolve_plaintext(&v["request"]);
    let plaintext_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // For RSA-OAEP, encrypt with the public key (or private — handler resolves)
    let encrypt_kid = if alg == "dir" {
        kid.clone()
    } else {
        kid_public.clone().unwrap_or_else(|| kid.clone())
    };

    // Encrypt
    let enc_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": encrypt_kid, "alg": alg, "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(
        enc_resp.get("ciphertext").is_some(),
        "Vector {filename}: missing ciphertext"
    );
    assert!(
        enc_resp.get("iv").is_some(),
        "Vector {filename}: missing iv"
    );
    assert!(
        enc_resp.get("tag").is_some(),
        "Vector {filename}: missing tag"
    );

    // For RSA-OAEP, encrypted_key must be present and non-empty
    if alg != "dir" {
        let ek = enc_resp["encrypted_key"]
            .as_str()
            .expect("RSA-OAEP encrypt must return encrypted_key");
        assert!(
            !ek.is_empty(),
            "Vector {filename}: encrypted_key must be non-empty for {alg}"
        );
    }

    // Decrypt — include encrypted_key if present
    let mut decrypt_payload = json!({
        "protected":  enc_resp["protected"],
        "iv":         enc_resp["iv"],
        "ciphertext": enc_resp["ciphertext"],
        "tag":        enc_resp["tag"]
    });
    if let Some(ek) = enc_resp.get("encrypted_key") {
        decrypt_payload["encrypted_key"] = ek.clone();
    }

    let dec_resp: Value =
        test_utils::post_json_with_uri(app, decrypt_payload, "/v1/crypto/decrypt").await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64 decode");
    assert_eq!(
        recovered, plaintext,
        "Vector {filename}: decrypt must yield original plaintext"
    );

    delete_key(app, &kid).await;
    Ok(())
}

async fn run_encrypt_decrypt_tamper_reject<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (kid, kid_public) = provision_key(app, key).await?;

    let alg = v["algorithm"].as_str().unwrap_or("dir");
    let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
    let plaintext = resolve_plaintext(&v["request"]);
    let plaintext_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    let encrypt_kid = if alg == "dir" {
        kid.clone()
    } else {
        kid_public.clone().unwrap_or_else(|| kid.clone())
    };

    // Encrypt
    let enc_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": encrypt_kid, "alg": alg, "enc": enc_alg, "data": plaintext_b64}),
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
    if let Some(ek) = enc_resp.get("encrypted_key") {
        decrypt_payload["encrypted_key"] = ek.clone();
    }

    match tamper_field {
        "protected" => {
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
        "encrypted_key" => {
            let ek_str = enc_resp["encrypted_key"]
                .as_str()
                .expect("encrypted_key must be present for tamper test");
            let mut ek_bytes = URL_SAFE_NO_PAD.decode(ek_str).unwrap();
            ek_bytes[0] ^= 0xFF;
            decrypt_payload["encrypted_key"] = Value::String(URL_SAFE_NO_PAD.encode(&ek_bytes));
        }
        f => panic!("Vector {filename}: unsupported tamper field: {f}"),
    }

    // Decrypt with tampered data must fail
    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&decrypt_payload)
        .to_request();
    let resp = actix_test::call_service(app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Vector {filename}: tampered {tamper_field} must cause decryption failure"
    );

    delete_key(app, &kid).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unwrap key tests (RSA-OAEP → import CEK → encrypt/decrypt round-trip)
// ═══════════════════════════════════════════════════════════════════════════════

/// Run an unwrap-key round-trip vector:
/// 1. Provision an RSA key pair
/// 2. Encrypt with RSA-OAEP (wraps a fresh CEK with the public key)
/// 3. Call `POST /v1/crypto/keys/unwrap` with the protected header + encrypted_key
/// 4. Use the unwrapped symmetric key to encrypt/decrypt a payload
async fn run_unwrap_key_round_trip<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let (kid, kid_public) = provision_key(app, key).await?;
    let pub_kid = kid_public.unwrap_or_else(|| kid.clone());

    let alg = v["algorithm"].as_str().expect("algorithm missing");
    let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
    let plaintext = resolve_plaintext(&v["request"]);
    let plaintext_b64 = URL_SAFE_NO_PAD.encode(&plaintext);

    // Step 1: Encrypt with RSA-OAEP → produces wrapped CEK
    let enc_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": pub_kid, "alg": alg, "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    let protected = enc_resp["protected"]
        .as_str()
        .expect("missing protected in encrypt response");
    let encrypted_key = enc_resp["encrypted_key"]
        .as_str()
        .expect("missing encrypted_key in encrypt response");

    // Step 2: Unwrap the CEK via POST /v1/crypto/keys/unwrap
    let unwrap_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"protected": protected, "encrypted_key": encrypted_key}),
        "/v1/crypto/keys/unwrap",
    )
    .await?;

    let sym_kid = unwrap_resp["kid"]
        .as_str()
        .expect("unwrap response missing kid");
    assert!(
        !sym_kid.is_empty(),
        "Vector {filename}: unwrap must return non-empty kid"
    );
    assert_eq!(
        unwrap_resp["kty"].as_str(),
        Some("oct"),
        "Vector {filename}: unwrapped key must be symmetric (kty=oct)"
    );
    assert_eq!(
        unwrap_resp["alg"].as_str(),
        Some(enc_alg),
        "Vector {filename}: unwrapped key alg must match enc"
    );

    // Step 3: Verify the unwrapped key works for encrypt + decrypt
    let enc2_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": sym_kid, "alg": "dir", "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    let dec_payload = json!({
        "protected":  enc2_resp["protected"],
        "iv":         enc2_resp["iv"],
        "ciphertext": enc2_resp["ciphertext"],
        "tag":        enc2_resp["tag"]
    });
    let dec_resp: Value =
        test_utils::post_json_with_uri(app, dec_payload, "/v1/crypto/decrypt").await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64 decode");
    assert_eq!(
        recovered, plaintext,
        "Vector {filename}: decrypt with unwrapped key must yield original plaintext"
    );

    // Cleanup
    delete_key(app, &kid).await;
    delete_key(app, sym_kid).await;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key lifecycle tests (create → use → delete → verify gone)
// ═══════════════════════════════════════════════════════════════════════════════

async fn run_key_lifecycle<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let key = &v["key"];
    let operation = v["operation"]
        .as_str()
        .unwrap_or_else(|| panic!("Vector {filename}: missing 'operation' field"));

    // ── Step 1: Create key ──────────────────────────────────────────────────
    let (kid, kid_public) = provision_key(app, key).await?;
    assert!(
        !kid.is_empty(),
        "Vector {filename}: POST /v1/crypto/keys must return non-empty kid"
    );

    // Verify asymmetric key-generation (no material provided) returns kid_public.
    // Imported private keys (material present via 'd') do not create a paired public key.
    let kty = key["kty"].as_str().unwrap_or("oct");
    let is_import = key.get("k").is_some() || key.get("d").is_some();
    if (kty == "EC" || kty == "RSA" || kty == "OKP") && !is_import {
        assert!(
            kid_public.is_some(),
            "Vector {filename}: asymmetric generated key must return kid_public"
        );
    }

    // ── Step 2: Use key ─────────────────────────────────────────────────────
    let plaintext = resolve_plaintext(&v["request"]);
    let data_b64 = URL_SAFE_NO_PAD.encode(&plaintext);
    let alg = v["algorithm"].as_str().expect("algorithm missing");

    match operation {
        "mac" => {
            let resp: Value = test_utils::post_json_with_uri(
                app,
                json!({"kid": kid, "alg": alg, "data": data_b64}),
                "/v1/crypto/mac",
            )
            .await?;
            assert!(
                resp.get("mac").is_some(),
                "Vector {filename}: MAC compute must return mac"
            );
        }
        "sign" => {
            let sign_kid = &kid;
            // For generated keys, verify with the public kid; for imports, use private kid
            let verify_kid = kid_public.as_deref().unwrap_or(&kid);
            let sign_result: KResult<Value> = test_utils::post_json_with_uri(
                app,
                json!({"kid": sign_kid, "alg": alg, "data": data_b64}),
                "/v1/crypto/sign",
            )
            .await;
            let resp = sign_result?;
            let protected = resp["protected"].as_str().expect("missing protected");
            let signature = resp["signature"].as_str().expect("missing signature");

            let verify_resp: Value = test_utils::post_json_with_uri(
                app,
                json!({"protected": protected, "data": data_b64, "signature": signature}),
                "/v1/crypto/verify",
            )
            .await?;
            assert_eq!(
                verify_resp["valid"].as_bool(),
                Some(true),
                "Vector {filename}: sign/verify must succeed"
            );
            assert_eq!(
                verify_resp["kid"].as_str(),
                Some(verify_kid),
                "Vector {filename}: verify kid mismatch"
            );
        }
        "encrypt" => {
            let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
            let encrypt_kid = if alg == "dir" {
                kid.clone()
            } else {
                kid_public.clone().unwrap_or_else(|| kid.clone())
            };
            let enc_resp: Value = test_utils::post_json_with_uri(
                app,
                json!({"kid": encrypt_kid, "alg": alg, "enc": enc_alg, "data": data_b64}),
                "/v1/crypto/encrypt",
            )
            .await?;
            assert!(
                enc_resp.get("ciphertext").is_some(),
                "Vector {filename}: encrypt must return ciphertext"
            );

            let mut decrypt_payload = json!({
                "protected":  enc_resp["protected"],
                "iv":         enc_resp["iv"],
                "ciphertext": enc_resp["ciphertext"],
                "tag":        enc_resp["tag"]
            });
            if let Some(ek) = enc_resp.get("encrypted_key") {
                decrypt_payload["encrypted_key"] = ek.clone();
            }

            let dec_resp: Value =
                test_utils::post_json_with_uri(app, decrypt_payload, "/v1/crypto/decrypt").await?;
            let recovered = URL_SAFE_NO_PAD
                .decode(dec_resp["data"].as_str().expect("missing data"))
                .expect("base64 decode");
            assert_eq!(
                recovered, plaintext,
                "Vector {filename}: decrypt must recover plaintext"
            );
        }
        op => panic!("Vector {filename}: unsupported lifecycle operation '{op}'"),
    }

    // ── Step 3: Delete key ──────────────────────────────────────────────────
    delete_key(app, &kid).await;

    // ── Step 4: Verify key is gone (operation must fail) ────────────────────
    let post_delete_req = match operation {
        "mac" => actix_test::TestRequest::post()
            .uri("/v1/crypto/mac")
            .set_json(&json!({"kid": kid, "alg": alg, "data": data_b64}))
            .to_request(),
        "sign" => actix_test::TestRequest::post()
            .uri("/v1/crypto/sign")
            .set_json(&json!({"kid": kid, "alg": alg, "data": data_b64}))
            .to_request(),
        "encrypt" => {
            let enc_alg = v["enc"].as_str().unwrap_or("A256GCM");
            actix_test::TestRequest::post()
                .uri("/v1/crypto/encrypt")
                .set_json(&json!({"kid": kid, "alg": alg, "enc": enc_alg, "data": data_b64}))
                .to_request()
        }
        op => panic!("Vector {filename}: unsupported post-delete check for '{op}'"),
    };
    let resp = actix_test::call_service(app, post_delete_req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Vector {filename}: using deleted key must fail"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expect-error tests (malformed requests, invalid payloads, edge cases)
// ═══════════════════════════════════════════════════════════════════════════════

/// Run a vector that expects an HTTP error response.
///
/// Vector format:
/// ```json
/// {
///   "type": "expect_error",
///   "endpoint": "/v1/crypto/encrypt",
///   "method": "POST",            // optional, defaults to POST
///   "body": { ... },             // raw JSON body to send (or null for no body)
///   "setup_key": { ... },        // optional: create a key first, inject kid into body
///   "expected_status": 400,      // expected HTTP status code
///   "expected_error": "bad_request"  // optional: assert error field in response
/// }
/// ```
async fn run_expect_error<S, B>(app: &S, v: &Value, filename: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let endpoint = v["endpoint"]
        .as_str()
        .unwrap_or_else(|| panic!("Vector {filename}: missing 'endpoint' field"));
    let method = v["method"].as_str().unwrap_or("POST");
    let expected_status = u16::try_from(
        v["expected_status"]
            .as_u64()
            .unwrap_or_else(|| panic!("Vector {filename}: missing 'expected_status' field")),
    )
    .expect("status code fits u16");

    // Optionally provision a key and inject kid into body
    let mut body = v["body"].clone();
    let mut kid_to_cleanup: Option<String> = None;

    if let Some(setup_key) = v.get("setup_key") {
        if !setup_key.is_null() {
            let (kid, kid_public) = provision_key(app, setup_key).await?;
            // Inject kid into body where "$KID" placeholder appears
            inject_kid(&mut body, &kid, kid_public.as_deref());
            kid_to_cleanup = Some(kid);
        }
    }

    // Build and send request
    let req = match method {
        "POST" => {
            if body.is_null() {
                actix_test::TestRequest::post()
                    .uri(endpoint)
                    .insert_header(("content-type", "application/json"))
                    .set_payload("")
                    .to_request()
            } else {
                actix_test::TestRequest::post()
                    .uri(endpoint)
                    .set_json(&body)
                    .to_request()
            }
        }
        "DELETE" => actix_test::TestRequest::delete().uri(endpoint).to_request(),
        "GET" => actix_test::TestRequest::get().uri(endpoint).to_request(),
        m => panic!("Vector {filename}: unsupported method '{m}'"),
    };

    let resp = actix_test::call_service(app, req).await;
    let status = resp.status().as_u16();

    assert_eq!(
        status, expected_status,
        "Vector {filename}: expected HTTP {expected_status}, got {status}"
    );

    // Optionally check the error code in the response body
    if let Some(expected_error) = v.get("expected_error").and_then(Value::as_str) {
        let resp_body = actix_test::read_body(resp).await;
        if let Ok(parsed) = serde_json::from_slice::<Value>(&resp_body) {
            if let Some(got_error) = parsed.get("error").and_then(Value::as_str) {
                assert_eq!(
                    got_error, expected_error,
                    "Vector {filename}: expected error code '{expected_error}', got '{got_error}'"
                );
            }
        }
    }

    // Cleanup provisioned key if any
    if let Some(kid) = kid_to_cleanup {
        delete_key(app, &kid).await;
    }

    Ok(())
}

/// Replace `"$KID"` and `"$KID_PUBLIC"` placeholders in a JSON body with actual key IDs.
fn inject_kid(body: &mut Value, kid: &str, kid_public: Option<&str>) {
    match body {
        Value::String(s) => {
            if s == "$KID" {
                *body = Value::String(kid.to_owned());
            } else if s == "$KID_PUBLIC" {
                *body = Value::String(kid_public.unwrap_or(kid).to_owned());
            }
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                inject_kid(val, kid, kid_public);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                inject_kid(val, kid, kid_public);
            }
        }
        _ => {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main test entry point — auto-discovers and runs all vectors
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_jose_vectors() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let vectors = discover_vectors();
    assert!(
        !vectors.is_empty(),
        "No JOSE vector files found in {}",
        vectors_dir().display()
    );

    let mut passed = 0;
    let mut errors: Vec<String> = Vec::new();

    for path in &vectors {
        let filename = path.file_name().unwrap().to_string_lossy();
        match run_vector(&app, path).await {
            Ok(()) => {
                passed += 1;
            }
            Err(e) => {
                errors.push(format!("{filename}: {e}"));
            }
        }
    }

    if errors.is_empty() {
        // All vectors passed
    } else {
        panic!(
            "JOSE vectors: {passed}/{} passed, {} failed:\n  {}",
            vectors.len(),
            errors.len(),
            errors.join("\n  ")
        );
    }

    Ok(())
}
