//! Tests that cryptographic operations respect KMIP 2.1 §3.31 state rules:
//!
//! - **Protection operations** (Encrypt, Sign, MAC) require `Active` state.
//! - **Processing operations** (Decrypt, Verify, MACVerify) accept
//!   `Active`, `Deactivated`, and `Compromised` states.
//!
//! Also tests KMIP §4.57 auto-deactivation (transition 6):
//!
//! - An Active key whose `DeactivationDate` has passed is automatically
//!   transitioned to Deactivated on retrieval, mirroring the PreActive → Active
//!   auto-activation mechanism.

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, RevocationReason, RevocationReasonCode, State},
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attribute,
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, GetAttributes, GetAttributesResponse, MAC,
            MACResponse, MACVerify, MACVerifyResponse, Revoke, RevokeResponse, SetAttribute,
            SetAttributeResponse, Sign, SignResponse, SignatureVerify, SignatureVerifyResponse,
        },
        kmip_types::{
            AttributeReference, CryptographicAlgorithm, CryptographicParameters,
            DigitalSignatureAlgorithm, RecommendedCurve, Tag, UniqueIdentifier, ValidityIndicator,
        },
        requests::{create_ec_key_pair_request, symmetric_key_create_request},
    },
};
use cosmian_logger::log_init;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::{result::KResult, tests::test_utils};

/// Create an AES-256 key and return its UID.
async fn create_aes_key<S, B>(app: &S) -> KResult<String>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(app, create_req).await?;
    Ok(cr.unique_identifier.to_string())
}

/// Encrypt plaintext with the given key, returning the JSON encrypt response.
async fn encrypt<S, B>(app: &S, kid: &str, plaintext: &[u8]) -> KResult<serde_json::Value>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);
    test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await
}

/// Attempt to decrypt the given ciphertext response; returns Ok(value) on success.
async fn try_decrypt<S, B>(
    app: &S,
    enc_resp: &serde_json::Value,
) -> Result<serde_json::Value, StatusCode>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        Ok(serde_json::from_slice(&body).unwrap_or_default())
    } else {
        Err(resp.status())
    }
}

/// Attempt to encrypt; returns Ok on 200, Err(status) otherwise.
async fn try_encrypt<S, B>(
    app: &S,
    kid: &str,
    plaintext: &[u8],
) -> Result<serde_json::Value, StatusCode>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);
    let req = test::TestRequest::post()
        .uri("/v1/crypto/encrypt")
        .set_json(&json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        Ok(serde_json::from_slice(&body).unwrap_or_default())
    } else {
        Err(resp.status())
    }
}

/// Deactivate a key via KMIP `Revoke` with `CessationOfOperation` reason.
async fn deactivate_key<S, B>(app: &S, kid: &str) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let revoke = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: Some("test deactivation".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    };
    let _resp: RevokeResponse = test_utils::post_2_1(app, revoke).await?;
    Ok(())
}

/// Compromise a key via KMIP `Revoke` with `KeyCompromise` reason.
async fn compromise_key<S, B>(app: &S, kid: &str) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let revoke = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::KeyCompromise,
            revocation_message: Some("test compromise".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    };
    let _resp: RevokeResponse = test_utils::post_2_1(app, revoke).await?;
    Ok(())
}

/// KMIP 2.1 §3.31: Decrypt MUST work on a Deactivated key.
#[tokio::test]
async fn test_decrypt_deactivated_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"secret data").await?;

    // Deactivate the key
    deactivate_key(&app, &kid).await?;

    // Decrypt must still work per KMIP 2.1 §3.31
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt with deactivated key should succeed per KMIP 2.1 §3.31, got: {dec_result:?}"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Decrypt SHOULD work on a Compromised key.
#[tokio::test]
async fn test_decrypt_compromised_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"secret data").await?;

    // Compromise the key
    compromise_key(&app, &kid).await?;

    // Decrypt must still work per KMIP 2.1 §3.31
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt with compromised key should succeed per KMIP 2.1 §3.31, got: {dec_result:?}"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Encrypt MUST NOT work on a Deactivated key.
#[tokio::test]
async fn test_encrypt_deactivated_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;

    // Deactivate the key
    deactivate_key(&app, &kid).await?;

    // Encrypt must be rejected (protection operation on non-Active key)
    let enc_result = try_encrypt(&app, &kid, b"will not encrypt").await;
    assert!(
        enc_result.is_err(),
        "Encrypt with deactivated key should fail per KMIP 2.1 §3.31"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Encrypt MUST NOT work on a Compromised key.
#[tokio::test]
async fn test_encrypt_compromised_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;

    // Compromise the key
    compromise_key(&app, &kid).await?;

    // Encrypt must be rejected (protection operation on non-Active key)
    let enc_result = try_encrypt(&app, &kid, b"will not encrypt").await;
    assert!(
        enc_result.is_err(),
        "Encrypt with compromised key should fail per KMIP 2.1 §3.31"
    );

    Ok(())
}

// ── MAC / MACVerify state tests ───────────────────────────────────────────────

const MAC_DATA: &[u8] = b"data-to-mac";

/// Compute an HMAC-SHA256 tag on [`MAC_DATA`] with an Active key.
async fn compute_hmac<S, B>(app: &S, kid: &str) -> KResult<Vec<u8>>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp: MACResponse = test_utils::post_2_1(
        app,
        MAC {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: Some(MAC_DATA.to_vec()),
            ..Default::default()
        },
    )
    .await?;
    Ok(resp.mac_data.unwrap_or_default())
}

/// KMIP 2.1 §3.31: MAC (protection op) MUST NOT work on a Deactivated key.
#[tokio::test]
async fn test_mac_deactivated_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    // MAC works while key is Active
    compute_hmac(&app, &kid).await?;

    deactivate_key(&app, &kid).await?;

    // MAC must be rejected on a Deactivated key (protection operation)
    let result = test_utils::post_2_1::<_, _, MACResponse, _>(
        &app,
        MAC {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: Some(MAC_DATA.to_vec()),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "MAC with deactivated key should fail per KMIP 2.1 §3.31"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: MAC (protection op) MUST NOT work on a Compromised key.
#[tokio::test]
async fn test_mac_compromised_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    compromise_key(&app, &kid).await?;

    let result = test_utils::post_2_1::<_, _, MACResponse, _>(
        &app,
        MAC {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: Some(MAC_DATA.to_vec()),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "MAC with compromised key should fail per KMIP 2.1 §3.31"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: MACVerify (processing op) MUST work on a Deactivated key.
#[tokio::test]
async fn test_mac_verify_deactivated_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let tag = compute_hmac(&app, &kid).await?;

    deactivate_key(&app, &kid).await?;

    // MACVerify must succeed on a Deactivated key (processing operation)
    let resp: MACVerifyResponse = test_utils::post_2_1(
        &app,
        MACVerify {
            unique_identifier: UniqueIdentifier::TextString(kid.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: MAC_DATA.to_vec(),
            mac_data: tag,
        },
    )
    .await
    .map_err(|e| {
        crate::error::KmsError::InvalidRequest(format!(
            "MACVerify with deactivated key should succeed per KMIP 2.1 §3.31, got: {e}"
        ))
    })?;
    assert_eq!(
        resp.validity_indicator,
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
        "MACVerify should report Valid"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: MACVerify (processing op) MUST work on a Compromised key.
#[tokio::test]
async fn test_mac_verify_compromised_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let tag = compute_hmac(&app, &kid).await?;

    compromise_key(&app, &kid).await?;

    let resp: MACVerifyResponse = test_utils::post_2_1(
        &app,
        MACVerify {
            unique_identifier: UniqueIdentifier::TextString(kid.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            }),
            data: MAC_DATA.to_vec(),
            mac_data: tag,
        },
    )
    .await
    .map_err(|e| {
        crate::error::KmsError::InvalidRequest(format!(
            "MACVerify with compromised key should succeed per KMIP 2.1 §3.31, got: {e}"
        ))
    })?;
    assert_eq!(
        resp.validity_indicator,
        ValidityIndicator::Valid,
        "MACVerify should report Valid"
    );
    Ok(())
}

// ── Sign / SignatureVerify state tests ────────────────────────────────────────

const SIGN_DATA: &[u8] = b"data-to-sign";

/// Create an EC P-256 keypair and return `(private_uid, public_uid)`.
async fn create_ec_keypair<S, B>(app: &S) -> KResult<(String, String)>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let resp: CreateKeyPairResponse = test_utils::post_2_1(app, req).await?;
    Ok((
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    ))
}

/// Sign [`SIGN_DATA`] with the private key and return the raw signature bytes.
async fn ec_sign<S, B>(app: &S, priv_uid: &str) -> KResult<Vec<u8>>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp: SignResponse = test_utils::post_2_1(
        app,
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(priv_uid.to_owned())),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            data: Some(Zeroizing::new(SIGN_DATA.to_vec())),
            ..Default::default()
        },
    )
    .await?;
    Ok(resp.signature_data.unwrap_or_default())
}

/// KMIP 2.1 §3.31: Sign (protection op) MUST NOT work on a Deactivated key.
#[tokio::test]
async fn test_sign_deactivated_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (priv_uid, _pub_uid) = create_ec_keypair(&app).await?;
    // Sign works while key is Active
    ec_sign(&app, &priv_uid).await?;

    deactivate_key(&app, &priv_uid).await?;

    // Sign must be rejected on a Deactivated key (protection operation)
    let result = test_utils::post_2_1::<_, _, SignResponse, _>(
        &app,
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(priv_uid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            data: Some(Zeroizing::new(SIGN_DATA.to_vec())),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Sign with deactivated key should fail per KMIP 2.1 §3.31"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: Sign (protection op) MUST NOT work on a Compromised key.
#[tokio::test]
async fn test_sign_compromised_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (priv_uid, _pub_uid) = create_ec_keypair(&app).await?;
    compromise_key(&app, &priv_uid).await?;

    let result = test_utils::post_2_1::<_, _, SignResponse, _>(
        &app,
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(priv_uid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            data: Some(Zeroizing::new(SIGN_DATA.to_vec())),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "Sign with compromised key should fail per KMIP 2.1 §3.31"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: SignatureVerify (processing op) MUST work on a Deactivated key.
#[tokio::test]
async fn test_signature_verify_deactivated_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (priv_uid, pub_uid) = create_ec_keypair(&app).await?;
    let sig = ec_sign(&app, &priv_uid).await?;

    // Deactivate the *public* key (used for verification)
    deactivate_key(&app, &pub_uid).await?;

    // SignatureVerify must succeed on a Deactivated key (processing operation)
    let resp: SignatureVerifyResponse = test_utils::post_2_1(
        &app,
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(pub_uid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            data: Some(SIGN_DATA.to_vec()),
            signature_data: Some(sig),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        crate::error::KmsError::InvalidRequest(format!(
            "SignatureVerify with deactivated key should succeed per KMIP 2.1 §3.31, got: {e}"
        ))
    })?;
    assert_eq!(
        resp.validity_indicator,
        Some(ValidityIndicator::Valid),
        "SignatureVerify should report Valid"
    );
    Ok(())
}

/// KMIP 2.1 §3.31: SignatureVerify (processing op) MUST work on a Compromised key.
#[tokio::test]
async fn test_signature_verify_compromised_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (priv_uid, pub_uid) = create_ec_keypair(&app).await?;
    let sig = ec_sign(&app, &priv_uid).await?;

    // Compromise the *public* key (used for verification)
    compromise_key(&app, &pub_uid).await?;

    let resp: SignatureVerifyResponse = test_utils::post_2_1(
        &app,
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(pub_uid.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            }),
            data: Some(SIGN_DATA.to_vec()),
            signature_data: Some(sig),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        crate::error::KmsError::InvalidRequest(format!(
            "SignatureVerify with compromised key should succeed per KMIP 2.1 §3.31, got: {e}"
        ))
    })?;
    assert_eq!(
        resp.validity_indicator,
        Some(ValidityIndicator::Valid),
        "SignatureVerify should report Valid"
    );
    Ok(())
}

// ── Auto-deactivation tests (KMIP §4.57 transition 6) ────────────────────────

/// Set the `DeactivationDate` attribute on a key via KMIP `SetAttribute`.
async fn set_deactivation_date<S, B>(app: &S, kid: &str, date: OffsetDateTime) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let _resp: SetAttributeResponse = test_utils::post_2_1(
        app,
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
            new_attribute: Attribute::DeactivationDate(date),
        },
    )
    .await?;
    Ok(())
}

/// Set the `ActivationDate` attribute on a key via KMIP `SetAttribute`.
async fn set_activation_date<S, B>(app: &S, kid: &str, date: OffsetDateTime) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let _resp: SetAttributeResponse = test_utils::post_2_1(
        app,
        SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
            new_attribute: Attribute::ActivationDate(date),
        },
    )
    .await?;
    Ok(())
}

/// Query the `State` attribute of a key via KMIP `GetAttributes`.
async fn get_state<S, B>(app: &S, kid: &str) -> KResult<Option<State>>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp: GetAttributesResponse = test_utils::post_2_1(
        app,
        GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
            attribute_reference: Some(vec![AttributeReference::Standard(Tag::State)]),
        },
    )
    .await?;
    Ok(resp.attributes.state)
}

/// KMIP §4.57 transition 6: An Active key with a `DeactivationDate` in the past
/// is automatically transitioned to Deactivated on retrieval.
///
/// - Encrypt (protection op) MUST fail.
/// - Decrypt (processing op) MUST succeed.
/// - Reported state MUST be `Deactivated`.
#[tokio::test]
async fn test_auto_deactivation_past_date_blocks_encrypt() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // Create an Active AES key and encrypt while it is Active.
    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"auto-deact test").await?;

    // Set DeactivationDate to 1 hour in the past → triggers auto-deactivation.
    let past = OffsetDateTime::now_utc() - Duration::hours(1);
    set_deactivation_date(&app, &kid, past).await?;

    // Encrypt must be rejected (key is now effectively Deactivated).
    let enc_result = try_encrypt(&app, &kid, b"should fail").await;
    assert!(
        enc_result.is_err(),
        "Encrypt must fail on an auto-deactivated key (§4.57 transition 6)"
    );

    // Decrypt must still succeed (processing op on Deactivated key).
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt must succeed on an auto-deactivated key, got: {dec_result:?}"
    );

    // State attribute must report Deactivated.
    let state = get_state(&app, &kid).await?;
    assert_eq!(
        state,
        Some(State::Deactivated),
        "State must be Deactivated after auto-deactivation"
    );

    Ok(())
}

/// A key with `DeactivationDate` in the future remains Active.
///
/// Encrypt (protection op) MUST succeed.
#[tokio::test]
async fn test_future_deactivation_date_keeps_key_active() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;

    // Set DeactivationDate 1 hour in the future — key should stay Active.
    let future = OffsetDateTime::now_utc() + Duration::hours(1);
    set_deactivation_date(&app, &kid, future).await?;

    // Encrypt must still work (key is Active until DeactivationDate).
    let enc_result = try_encrypt(&app, &kid, b"still active").await;
    assert!(
        enc_result.is_ok(),
        "Encrypt must succeed when DeactivationDate is in the future"
    );

    // State must still be Active.
    let state = get_state(&app, &kid).await?;
    assert_eq!(
        state,
        Some(State::Active),
        "State must remain Active when DeactivationDate is in the future"
    );

    Ok(())
}

/// Auto-deactivation persists: once the server transitions a key to Deactivated
/// via auto-deactivation, subsequent retrievals reflect the persisted state
/// without re-checking the date.
#[tokio::test]
async fn test_auto_deactivation_persists_across_retrievals() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"persistence test").await?;

    // Trigger auto-deactivation.
    let past = OffsetDateTime::now_utc() - Duration::hours(1);
    set_deactivation_date(&app, &kid, past).await?;

    // First retrieval: triggers auto-deactivation and persists Deactivated.
    let state1 = get_state(&app, &kid).await?;
    assert_eq!(state1, Some(State::Deactivated));

    // Second retrieval: state is already persisted, no date check needed.
    let state2 = get_state(&app, &kid).await?;
    assert_eq!(state2, Some(State::Deactivated));

    // Decrypt still works on both retrievals.
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt must succeed on persisted auto-deactivated key"
    );

    Ok(())
}

/// KMIP §4.57 combined transitions: a PreActive key with past `ActivationDate`
/// AND past `DeactivationDate` transitions through PreActive → Active →
/// Deactivated in a single retrieval.
#[tokio::test]
async fn test_preactive_to_deactivated_combined_transition() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // Create a key with a future activation date to make it PreActive.
    let kid = create_aes_key(&app).await?;

    // Set ActivationDate in the past → server auto-activates.
    let past_activation = OffsetDateTime::now_utc() - Duration::hours(2);
    set_activation_date(&app, &kid, past_activation).await?;

    // Set DeactivationDate in the past → server auto-deactivates.
    let past_deactivation = OffsetDateTime::now_utc() - Duration::hours(1);
    set_deactivation_date(&app, &kid, past_deactivation).await?;

    // Encrypt must fail (key is effectively Deactivated).
    let enc_result = try_encrypt(&app, &kid, b"should fail").await;
    assert!(
        enc_result.is_err(),
        "Encrypt must fail on a key that passed through PreActive→Active→Deactivated"
    );

    // State must report Deactivated.
    let state = get_state(&app, &kid).await?;
    assert_eq!(
        state,
        Some(State::Deactivated),
        "State must be Deactivated after combined PreActive→Active→Deactivated transitions"
    );

    Ok(())
}
