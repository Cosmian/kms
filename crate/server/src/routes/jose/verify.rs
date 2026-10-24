use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        kmip_operations::SignatureVerify,
        kmip_types::{UniqueIdentifier, ValidityIndicator},
    },
};
use cosmian_logger::trace;
use serde::Deserialize;

use super::{
    CryptoApiError, CryptoResult, JoseAlgorithm, VerifyRequest,
    VerifyResponse as CryptoVerifyResponse, b64_decode, ecdsa_coord_size, ecdsa_p1363_to_der,
    ensure_json_object, jose_to_kmip_params,
};
use crate::{core::KMS, error::KmsError};

#[derive(Deserialize)]
struct JwsProtectedHeader<'a> {
    #[serde(default, borrow, deserialize_with = "super::lenient_str")]
    kid: Option<std::borrow::Cow<'a, str>>,
    #[serde(default, borrow, deserialize_with = "super::lenient_str")]
    alg: Option<std::borrow::Cow<'a, str>>,
}
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

    trace!(user = user.as_str(), "POST /v1/crypto/verify");

    let header_bytes = b64_decode("protected", &body.protected)?;
    ensure_json_object(&header_bytes)?;
    let header: JwsProtectedHeader<'_> = serde_json::from_slice(&header_bytes).map_err(|e| {
        CryptoApiError::BadRequest(format!(
            "Field 'protected' is not valid JSON after base64url decode: {e}"
        ))
    })?;

    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| {
            CryptoApiError::BadRequest("Protected header missing required 'kid' field".to_owned())
        })?
        .to_owned();

    let alg_str = header.alg.as_deref().ok_or_else(|| {
        CryptoApiError::BadRequest("Protected header missing required 'alg' field".to_owned())
    })?;

    // RFC 7515 §4.1.1 / RFC 8725 §2.1: explicitly reject the "none" algorithm.
    // This guard runs before enum parsing so the security intent is clear even if
    // new algorithm entries are added to JoseAlgorithm in the future.
    if alg_str == "none" {
        return Err(CryptoApiError::UnsupportedAlgorithm(
            "alg 'none' is not permitted — all payloads must be cryptographically protected"
                .to_owned(),
        ));
    }

    let alg: JoseAlgorithm = alg_str
        .parse()
        .map_err(CryptoApiError::UnsupportedAlgorithm)?;

    b64_decode("data", &body.data)?;

    // RFC 7515 §2 — body.protected is already base64url; body.data is the payload base64url
    let mut signing_input_bytes = Vec::with_capacity(body.protected.len() + 1 + body.data.len());
    signing_input_bytes.extend_from_slice(body.protected.as_bytes());
    signing_input_bytes.push(b'.');
    signing_input_bytes.extend_from_slice(body.data.as_bytes());

    let signature_bytes = b64_decode("signature", &body.signature)?;
    // RFC 7518 §3.4: ECDSA JWS signatures are in fixed-size r||s (IEEE P1363) format.
    // The KMIP SignatureVerify operation expects DER/ASN.1 encoding.
    let kmip_signature = if ecdsa_coord_size(alg).is_some() {
        ecdsa_p1363_to_der(&signature_bytes)?
    } else {
        signature_bytes
    };
    let kmip_params = jose_to_kmip_params(alg, None)?;
    let verify_req = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(signing_input_bytes),
        signature_data: Some(kmip_signature),
        ..Default::default()
    };

    let valid = match kms.signature_verify(verify_req, &user).await {
        Ok(resp) => matches!(resp.validity_indicator, Some(ValidityIndicator::Valid)),
        // The key cannot verify at all (wrong type or usage mask): a caller error, not a
        // bad signature.
        Err(KmsError::Kmip21Error(
            reason @ (ErrorReason::Invalid_Object_Type
            | ErrorReason::Incompatible_Cryptographic_Usage_Mask),
            msg,
        )) => {
            return Err(CryptoApiError::from(KmsError::Kmip21Error(reason, msg)));
        }
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
