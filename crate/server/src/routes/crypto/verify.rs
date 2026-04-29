use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
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
#[post("/verify")]
pub(crate) async fn verify(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<VerifyRequest>,
) -> CryptoResult<CryptoVerifyResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/verify");

    let header_bytes = b64_decode("protected", &body.protected)?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|e| {
        CryptoApiError::BadRequest(format!(
            "Field 'protected' is not valid JSON after base64url decode: {e}"
        ))
    })?;

    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'kid' field".to_owned())
        })?
        .to_owned();

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'alg' field".to_owned())
        })?
        .to_owned();

    b64_decode("data", &body.data)?;

    // RFC 7515 §2 — body.protected is already base64url; body.data is the payload base64url
    let signing_input = format!("{}.{}", body.protected, body.data);
    let signing_input_bytes = signing_input.into_bytes();

    let signature_bytes = b64_decode("signature", &body.signature)?;
    let kmip_params = jose_to_kmip_params(&alg, None)?;
    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(signing_input_bytes),
        signature_data: Some(signature_bytes),
        ..Default::default()
    };

    let valid = match kms.signature_verify(verify_req, &user).await {
        Ok(resp) => matches!(resp.validity_indicator, Some(ValidityIndicator::Valid)),
        Err(e) => {
            let api_err = CryptoApiError::from(e);
            match api_err {
                // A crypto failure during verification means the signature bytes are
                // malformed or otherwise unverifiable — treat as invalid (not an error).
                CryptoApiError::CryptoFailure(_) => false,
                other => return Err(other),
            }
        }
    };

    Ok(Json(CryptoVerifyResponse { kid, valid }))
}
