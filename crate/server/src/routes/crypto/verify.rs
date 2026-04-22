use std::sync::Arc;

use actix_web::{HttpRequest, post, web::{Data, Json}};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::SignatureVerify,
    kmip_types::{UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::trace;

use super::{
    CryptoApiError, CryptoResult, VerifyRequest, VerifyResponse as CryptoVerifyResponse,
    b64_decode, jose_to_kmip_params,
};
use crate::core::KMS;

/// `POST /v1/crypto/verify` — Verify a detached JWS signature.
///
/// Follows RFC 7515 §2:
/// JWS Signing Input = `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))`
///
/// The `protected` field must be exactly as returned by `POST /v1/crypto/sign`
/// and `data` must be the same payload base64url.
#[post("/v1/crypto/verify")]
pub(crate) async fn verify(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<VerifyRequest>,
) -> CryptoResult<CryptoVerifyResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/verify");

    // 1. Decode protected header → extract kid and alg
    let header_bytes = b64_decode("protected", &body.protected)?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|e| {
            CryptoApiError::BadRequest(format!(
                "Field 'protected' is not valid JSON after base64url decode: {e}"
            ))
        })?;

    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "Protected header missing required 'kid' field".to_owned(),
            )
        })?
        .to_owned();

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest(
                "Protected header missing required 'alg' field".to_owned(),
            )
        })?
        .to_owned();

    // 2. Validate payload: must be valid base64url
    b64_decode("data", &body.data)?;

    // 3. Reconstruct JWS Signing Input per RFC 7515 §2 — exactly as in sign
    //    signing_input = ASCII(protected_b64 + "." + payload_b64)
    //    Note: body.protected is already the base64url-encoded protected header
    let signing_input = format!("{}.{}", body.protected, body.data);
    let signing_input_bytes = signing_input.into_bytes();

    // 4. Decode signature
    let signature_bytes = b64_decode("signature", &body.signature)?;

    // 5. Map JOSE alg to KMIP parameters
    let kmip_params = jose_to_kmip_params(&alg, None)?;

    // 6. Call KMS signature_verify
    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(signing_input_bytes),
        signature_data: Some(signature_bytes),
        ..Default::default()
    };

    let resp = kms
        .signature_verify(verify_req, &user)
        .await
        .map_err(CryptoApiError::from)?;

    let valid = matches!(
        resp.validity_indicator,
        Some(ValidityIndicator::Valid)
    );

    Ok(Json(CryptoVerifyResponse { kid, valid }))
}
