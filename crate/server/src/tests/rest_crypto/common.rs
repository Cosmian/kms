//! Shared helpers reused across REST crypto test modules.

use actix_http::Request;
use actix_web::{
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_attributes::Attributes,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, SymmetricKey},
    kmip_operations::ImportResponse,
    kmip_types::{CryptographicAlgorithm, KeyFormatType},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{result::KResult, tests::test_utils};

/// AES-GCM encrypt → decrypt round-trip for any key size and `enc` algorithm string.
pub(super) async fn aes_gcm_round_trip<S, B>(app: &S, bits: usize, enc_alg: &str) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_operations::CreateResponse, requests::symmetric_key_create_request,
    };

    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        bits,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let create_resp: CreateResponse = test_utils::post_2_1(app, create_req).await?;
    let kid = create_resp.unique_identifier.to_string();

    let plaintext_b64 = URL_SAFE_NO_PAD.encode(b"Hello, REST crypto API!");

    let enc_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": "dir", "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(enc_resp.get("ciphertext").is_some(), "missing ciphertext");
    assert!(enc_resp.get("iv").is_some(), "missing iv");
    assert!(enc_resp.get("tag").is_some(), "missing tag");

    let dec_resp: Value = test_utils::post_json_with_uri(
        app,
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
    assert_eq!(recovered, b"Hello, REST crypto API!");
    Ok(())
}

/// Sign `data` then verify the signature for a given algorithm and key pair.
/// Also asserts that tampered data yields `valid=false` (or a non-200 response).
pub(super) async fn sign_verify_round_trip<S, B>(
    app: &S,
    alg: &str,
    private_kid: &str,
    public_kid: &str,
) -> KResult<()>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(b"data to sign");

    let sign_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": private_kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/sign",
    )
    .await?;

    let protected = sign_resp["protected"].as_str().expect("missing protected");
    let signature = sign_resp["signature"].as_str().expect("missing signature");

    let verify_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"protected": protected, "data": data_b64, "signature": signature}),
        "/v1/crypto/verify",
    )
    .await?;

    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "verify should return valid=true; response: {verify_resp}"
    );
    assert_eq!(
        verify_resp["kid"].as_str().expect("missing kid"),
        public_kid,
        "verify kid should be the public key"
    );

    // Tampered data → non-200 or valid=false
    let tampered_b64 = URL_SAFE_NO_PAD.encode(b"tampered data");
    let req = test::TestRequest::post()
        .uri("/v1/crypto/verify")
        .set_json(&json!({"protected": protected, "data": tampered_b64, "signature": signature}))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        let parsed: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            parsed["valid"].as_bool(),
            Some(false),
            "tampered data should yield valid=false"
        );
    }

    Ok(())
}

/// Import a raw symmetric key with `MACGenerate | MACVerify` usage mask.
///
/// Returns the KMS unique identifier of the imported key.
pub(super) async fn import_hmac_key<S, B>(app: &S, key_bytes: Vec<u8>) -> KResult<String>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: actix_web::body::MessageBody,
{
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::requests::import_object_request;

    let key_len_bits = i32::try_from(key_bytes.len() * 8).expect("key length fits i32");
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(key_len_bits),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::MACGenerate | CryptographicUsageMask::MACVerify,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        ..Attributes::default()
    };
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::from(key_bytes),
                },
                attributes: Some(attributes.clone()),
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(key_len_bits),
            key_wrapping_data: None,
        },
    });
    let import_req = import_object_request(
        VENDOR_ID_COSMIAN,
        None,
        object,
        Some(attributes),
        false,
        false,
        EMPTY_TAGS,
    )?;
    let resp: ImportResponse = test_utils::post_2_1(app, import_req).await?;
    Ok(resp.unique_identifier.to_string())
}
