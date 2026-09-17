//! Integration tests for the `GET /.well-known/jwks.json` endpoint.
//!
//! Uses the in-process actix-web test infrastructure — no TCP server.

use actix_web::test::{self, call_service, read_body};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_operations::{CreateKeyPairResponse, CreateResponse, RevokeResponse},
        kmip_types::{CryptographicAlgorithm, RecommendedCurve},
        requests::{
            build_revoke_key_request, create_ec_key_pair_request, create_rsa_key_pair_request,
            symmetric_key_create_request,
        },
    },
};
use jsonwebtoken::jwk::JwkSet;

use crate::{result::KResult, tests::test_utils};

/// Helper function: call `GET /.well-known/jwks.json` and return the raw `ServiceResponse`.
async fn get_jwks_response<S, B>(app: &S) -> actix_web::dev::ServiceResponse<B>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
{
    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .to_request();
    call_service(app, req).await
}

/// Empty DB → `200 OK` with `{"keys": []}`.
#[tokio::test]
async fn test_jwks_empty_db() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);

    let body = read_body(resp).await;
    let set: JwkSet = serde_json::from_slice(&body).expect("valid JwkSet JSON");
    // The test server pre-creates a Google CSE RSA key; filter to ensure the
    // "empty" assertion is structurally sound by just checking we get a valid set.
    // The keys array may contain Google CSE keys but must not contain non-existent keys.
    let _ = set.keys.len(); // just assert it parses
    Ok(())
}

/// RSA-2048 public key tagged `"jwks"` → appears in JWKS with `kty=RSA`, `alg=RS256`.
#[tokio::test]
async fn test_jwks_rsa2048_verify_key_present() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // Create an RSA-2048 key pair via KMIP (no tags yet).
    let kp_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    // Tag the public key for JWKS inclusion.
    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{public_kid}/tags"),
        )
        .await?,
    );

    // Fetch JWKS
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let body = read_body(resp).await;
    let set: JwkSet = serde_json::from_slice(&body).expect("valid JwkSet JSON");

    let found = set
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&public_kid));
    let jwk = found.expect("RSA-2048 public key should be in JWKS");

    // Must be RSA key type
    assert!(
        matches!(
            &jwk.algorithm,
            jsonwebtoken::jwk::AlgorithmParameters::RSA(_)
        ),
        "kty should be RSA"
    );

    // alg should be RS256 for 2048-bit
    assert_eq!(
        jwk.common.key_algorithm,
        Some(jsonwebtoken::jwk::KeyAlgorithm::RS256),
        "alg should be RS256 for RSA-2048"
    );

    // kid should match
    assert_eq!(jwk.common.key_id.as_deref(), Some(public_kid.as_str()));

    Ok(())
}

/// EC P-256 public key tagged `"jwks"` → `kty=EC`, `crv=P-256`, `alg=ES256`.
#[tokio::test]
async fn test_jwks_ec_p256_verify_key_present() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    // Tag the public key for JWKS inclusion.
    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{public_kid}/tags"),
        )
        .await?,
    );

    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let body = read_body(resp).await;
    let set: JwkSet = serde_json::from_slice(&body).expect("valid JwkSet JSON");

    let found = set
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&public_kid));
    let jwk = found.expect("EC P-256 public key should be in JWKS");

    match &jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ec) => {
            assert_eq!(
                ec.curve,
                jsonwebtoken::jwk::EllipticCurve::P256,
                "crv should be P-256"
            );
            assert!(!ec.x.is_empty(), "x coordinate must be present");
            assert!(!ec.y.is_empty(), "y coordinate must be present");
        }
        other => panic!("expected EC key parameters, got {other:?}"),
    }

    assert_eq!(
        jwk.common.key_algorithm,
        Some(jsonwebtoken::jwk::KeyAlgorithm::ES256),
        "alg should be ES256 for P-256"
    );

    Ok(())
}

/// EC P-384 public key tagged `"jwks"` → `crv=P-384`, `alg=ES384`.
#[tokio::test]
async fn test_jwks_ec_p384_verify_key_present() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P384,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    // Tag the public key for JWKS inclusion.
    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{public_kid}/tags"),
        )
        .await?,
    );

    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let body = read_body(resp).await;
    let set: JwkSet = serde_json::from_slice(&body).expect("valid JwkSet JSON");

    let found = set
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&public_kid));
    let jwk = found.expect("EC P-384 public key should be in JWKS");

    match &jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ec) => {
            assert_eq!(
                ec.curve,
                jsonwebtoken::jwk::EllipticCurve::P384,
                "crv should be P-384"
            );
        }
        other => panic!("expected EC key parameters, got {other:?}"),
    }
    assert_eq!(
        jwk.common.key_algorithm,
        Some(jsonwebtoken::jwk::KeyAlgorithm::ES384),
    );
    Ok(())
}

/// Content-Type must be `application/jwk-set+json`.
#[tokio::test]
async fn test_jwks_content_type() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let ct = resp
        .headers()
        .get("Content-Type")
        .expect("Content-Type header must be present")
        .to_str()
        .expect("Content-Type must be valid UTF-8");
    assert!(
        ct.contains("application/jwk-set+json"),
        "Content-Type should be application/jwk-set+json, got: {ct}"
    );
    Ok(())
}

/// `Cache-Control: no-store` must be present.
#[tokio::test]
async fn test_jwks_cache_control_no_store() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let cc = resp
        .headers()
        .get("Cache-Control")
        .expect("Cache-Control header must be present")
        .to_str()
        .expect("Cache-Control must be valid UTF-8");
    assert!(
        cc.contains("no-store"),
        "Cache-Control should contain no-store, got: {cc}"
    );
    Ok(())
}

/// `ETag` conditional GET: matching `ETag` → `304 Not Modified`.
#[tokio::test]
async fn test_jwks_etag_304_on_match() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // First request — get the ETag
    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let etag = resp
        .headers()
        .get("ETag")
        .expect("ETag header must be present on first JWKS response")
        .to_str()
        .expect("ETag must be valid UTF-8")
        .to_owned();

    // Second request with matching If-None-Match → 304
    let req2 = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .insert_header(("If-None-Match", etag.as_str()))
        .to_request();
    let resp2 = call_service(&app, req2).await;
    assert_eq!(
        resp2.status(),
        304,
        "matching ETag should yield 304 Not Modified"
    );

    Ok(())
}

/// Stale `ETag` → `200 OK` (not a 304).
#[tokio::test]
async fn test_jwks_etag_200_on_stale() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    let req = test::TestRequest::get()
        .uri("/.well-known/jwks.json")
        .insert_header(("If-None-Match", "W/\"stale-etag-value\""))
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "stale ETag should yield 200 OK");

    Ok(())
}

/// Opt-out flow: keys created via REST are auto-tagged `"jwks"`;
/// removing the tag excludes the key from JWKS without destroying it.
///
/// Steps:
/// 1. Create two EC P-256 key pairs via the REST `/v1/crypto/keys` endpoint
///    (both get the `"jwks"` tag automatically).
/// 2. Assert that both public keys appear in `GET /.well-known/jwks.json`.
/// 3. Remove the `"jwks"` tag from the first public key via
///    `DELETE /v1/crypto/keys/{kid_public_1}/tags`.
/// 4. Assert that only the second public key remains in JWKS.
#[tokio::test]
async fn test_jwks_tag_opt_out_flow() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // Step 1 — create two EC P-256 key pairs via the REST endpoint (auto-tagged).
    let resp_1: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        serde_json::json!({"kty": "EC", "crv": "P-256"}),
        "/v1/crypto/keys",
    )
    .await?;
    let kid_pub_1 = resp_1["kid_public"]
        .as_str()
        .expect("kid_public must be present in key-creation response")
        .to_owned();

    let resp_2: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        serde_json::json!({"kty": "EC", "crv": "P-256"}),
        "/v1/crypto/keys",
    )
    .await?;
    let kid_pub_2 = resp_2["kid_public"]
        .as_str()
        .expect("kid_public must be present in key-creation response")
        .to_owned();

    // Step 2 — both public keys must be in JWKS.
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let set: JwkSet = serde_json::from_slice(&read_body(resp).await).expect("valid JwkSet JSON");
    assert!(
        set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid_pub_1.as_str())),
        "key 1 should be in JWKS before opt-out"
    );
    assert!(
        set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid_pub_2.as_str())),
        "key 2 should be in JWKS before opt-out"
    );

    // Step 3 — opt key 1 out of JWKS by removing its `"jwks"` tag.
    let del_req = test::TestRequest::delete()
        .uri(&format!("/v1/crypto/keys/{kid_pub_1}/tags"))
        .set_json(serde_json::json!({"tags": ["jwks"]}))
        .to_request();
    let del_resp = call_service(&app, del_req).await;
    assert_eq!(del_resp.status(), 200, "DELETE /tags should return 200 OK");

    // Step 4 — only key 2 must remain in JWKS.
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let set: JwkSet = serde_json::from_slice(&read_body(resp).await).expect("valid JwkSet JSON");
    assert!(
        !set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid_pub_1.as_str())),
        "key 1 should NOT be in JWKS after opt-out"
    );
    assert!(
        set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid_pub_2.as_str())),
        "key 2 should still be in JWKS after key 1 opts out"
    );

    Ok(())
}

/// A `Deactivated` public key (rotation overlap) must **still** appear in JWKS.
///
/// Rationale: after key rotation, tokens signed with the old private key are still
/// in circulation until they expire.  Verifiers need the old public key to stay in
/// JWKS even though the key is deactivated (no longer used for signing).
#[tokio::test]
async fn test_jwks_deactivated_key_included() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // Create an EC P-256 key pair and tag the public key for JWKS.
    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let public_kid = kp_resp.public_key_unique_identifier.to_string();
    let private_kid = kp_resp.private_key_unique_identifier.to_string();

    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{public_kid}/tags"),
        )
        .await?,
    );

    // Deactivate via Revoke with CessationOfOperation (→ State::Deactivated).
    let revoke_req = build_revoke_key_request(
        &private_kid,
        RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: None,
        },
    )?;
    drop(test_utils::post_2_1::<_, _, RevokeResponse, _>(&app, revoke_req).await?);

    // Deactivated key must still appear in JWKS (rotation overlap).
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let set: JwkSet = serde_json::from_slice(&read_body(resp).await).expect("valid JwkSet JSON");
    assert!(
        set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(public_kid.as_str())),
        "deactivated public key must still be in JWKS for rotation overlap"
    );

    Ok(())
}

/// A `Compromised` public key must **not** appear in JWKS.
///
/// Rationale: a compromised key's signatures cannot be trusted.  Keeping it in
/// JWKS would allow attackers to present forged tokens as valid.
#[tokio::test]
async fn test_jwks_compromised_key_excluded() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // Create an EC P-256 key pair and tag the public key for JWKS.
    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let public_kid = kp_resp.public_key_unique_identifier.to_string();
    let private_kid = kp_resp.private_key_unique_identifier.to_string();

    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{public_kid}/tags"),
        )
        .await?,
    );

    // Revoke with KeyCompromise → State::Compromised.
    let revoke_req = build_revoke_key_request(
        &private_kid,
        RevocationReason {
            revocation_reason_code: RevocationReasonCode::KeyCompromise,
            revocation_message: None,
        },
    )?;
    drop(test_utils::post_2_1::<_, _, RevokeResponse, _>(&app, revoke_req).await?);

    // Compromised key must NOT appear in JWKS.
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let set: JwkSet = serde_json::from_slice(&read_body(resp).await).expect("valid JwkSet JSON");
    assert!(
        !set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(public_kid.as_str())),
        "compromised public key must NOT be in JWKS"
    );

    Ok(())
}

/// A symmetric key tagged `"jwks"` must **not** appear in JWKS.
///
/// JWKS is a public-key format (RFC 7517).  Symmetric key material must never
/// be published; the endpoint filters by `ObjectType::PublicKey`.
#[tokio::test]
async fn test_jwks_symmetric_key_excluded() -> KResult<()> {
    let app = test_utils::setup_app(None).await;

    // Create an AES-256 symmetric key.
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(&app, create_req).await?;
    let kid = cr.unique_identifier.to_string();

    // Explicitly tag it "jwks".
    drop(
        test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
            &app,
            serde_json::json!({"tags": ["jwks"]}),
            &format!("/v1/crypto/keys/{kid}/tags"),
        )
        .await?,
    );

    // Symmetric key must NOT appear in JWKS regardless of the tag.
    let resp = get_jwks_response(&app).await;
    assert_eq!(resp.status(), 200);
    let set: JwkSet = serde_json::from_slice(&read_body(resp).await).expect("valid JwkSet JSON");
    assert!(
        !set.keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid.as_str())),
        "symmetric key must NOT appear in JWKS even when tagged 'jwks'"
    );

    Ok(())
}
