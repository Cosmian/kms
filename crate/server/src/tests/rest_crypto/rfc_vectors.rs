//! RFC 7515 test vectors — known-answer and known-key round-trip tests.
//!
//! # Coverage
//!
//! ## Not yet implemented (blocked - to be added in future versions)
//!
//! | RFC appendix | Blocked by |
//! |---|---|
//! | RFC 7516 §A.1 — RSAES-OAEP + A128GCM | RSA-OAEP key management not implemented |
//! | RFC 7516 §A.2 — RSAES-PKCS1-v1_5 + A128CBC-HS256 | RSA-PKCS1v1.5 + AES-CBC not implemented |
//! | RFC 7516 §A.3 — AES Key Wrap + A128CBC-HS256 | AES key-wrap + AES-CBC not implemented |
//! | RFC 7516 §A.5 — dir + A128CBC-HS256 | AES-CBC not implemented; no normative GCM vector |
//! | RFC 7518 §B — AES_CBC_HMAC_SHA2 KAT | AES-CBC not implemented |
//! | RFC 7518 §C — ECDH-ES key agreement | ECDH-ES not implemented |

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateKeyPairResponse,
    kmip_types::RecommendedCurve,
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

/// RFC 7515 §Appendix A.1 — HMAC-SHA256 known-answer test.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1>
///
/// Key, signing input, and expected MAC (`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`)
/// are taken verbatim from the RFC. Any regression in the HS256 code path will
/// produce a different MAC and fail with a clear message.
#[tokio::test]
async fn test_rfc7515_a1_hs256_known_answer() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    // RFC 7515 §A.1 — 512-bit key (base64url):
    //   AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
    let key_bytes = URL_SAFE_NO_PAD
        .decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .expect("RFC 7515 A.1 key is valid base64url");
    let kid = super::common::import_hmac_key(&app, key_bytes).await?;

    // RFC 7515 §A.1 — JWS Signing Input:
    //   ASCII(BASE64URL(UTF8(Protected Header)) || '.' || BASE64URL(Payload))
    //   Embedded CR+LF sequences are part of the RFC test data.
    let signing_input: &[u8] =
        b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9\
          .eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    let data_b64 = URL_SAFE_NO_PAD.encode(signing_input);

    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;

    // RFC 7515 §A.1 — expected MAC (base64url):
    let got_mac = compute_resp["mac"].as_str().expect("missing mac field");
    assert_eq!(
        got_mac, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "RFC 7515 §A.1 (https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1): \
         HS256 HMAC-SHA256 over JWS signing input must match the known-answer vector"
    );

    // Verify the correct MAC is accepted
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": got_mac}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "RFC 7515 §A.1: correct MAC must verify as valid=true"
    );

    Ok(())
}

/// RFC 7515 §Appendix A.2 — RS256 (RSA-2048) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2>
///
/// The RFC JWK uses a 2048-bit RSA key. We generate a fresh 2048-bit key pair
/// and confirm sign → verify succeeds end-to-end.
///
/// **Not a known-answer test** because our `/v1/crypto/verify` requires a `kid`
/// field in the JWS protected header; the RFC compact JWS header is
/// `{"alg":"RS256"}` (no `kid`). When kid-less verification is supported,
/// replace this with a full known-answer test using the exact RFC signing input
/// and signature from Appendix A.2.
#[tokio::test]
async fn test_rfc7515_a2_rs256_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "RS256", &private_kid, &public_kid).await
}

/// RFC 7515 §Appendix A.3 — ES256 (ECDSA P-256) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3>
///
/// RFC JWK: `kty=EC, crv=P-256`, private scalar `d`.
/// The RFC signature is non-deterministic (random nonce); we confirm
/// sign → verify succeeds for a freshly generated P-256 key pair.
///
/// Full known-answer test deferred — same `kid` constraint as A.2.
#[tokio::test]
async fn test_rfc7515_a3_es256_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "ES256", &private_kid, &public_kid).await
}

/// RFC 7515 §Appendix A.4 — ES512 (ECDSA P-521) known-key round-trip.
///
/// Source: <https://www.rfc-editor.org/rfc/rfc7515#appendix-A.4>
///
/// RFC JWK: `kty=EC, crv=P-521`.
/// Same constraints as A.3 (non-deterministic signature + `kid` requirement).
/// Full known-answer test deferred until kid-less verify is supported.
#[tokio::test]
async fn test_rfc7515_a4_es512_known_key_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P521,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "ES512", &private_kid, &public_kid).await
}
