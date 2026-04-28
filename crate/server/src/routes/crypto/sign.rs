use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_operations::Sign as KmipSign,
    kmip_types::{LinkType, UniqueIdentifier},
};
use cosmian_logger::trace;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    CryptoApiError, CryptoResult, SignRequest, SignResponse as CryptoSignResponse, b64_decode,
    b64_encode, jose_to_kmip_params,
};
use crate::core::{KMS, retrieve_object_utils::retrieve_object_for_operation};

/// `POST /v1/crypto/sign` — Detached JWS signature over arbitrary payload.
///
/// Follows RFC 7515 §2:
/// JWS Signing Input = `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))`
///
/// The payload is NOT included in the response (detached content per RFC 7515 Appendix F).
#[post("/sign")]
pub(crate) async fn sign(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<SignRequest>,
) -> CryptoResult<CryptoSignResponse> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/sign kid={}", body.kid);

    // JWS convention (RFC 7515 §4.1.4): `kid` in the protected header identifies
    // the public key that can verify the signature, not the signing private key.
    // Look up the private key's linked public key; fall back to body.kid for
    // symmetric keys and standalone keys that have no PublicKeyLink.
    let signing_kid = {
        let owm =
            retrieve_object_for_operation(&body.kid, KmipOperation::GetAttributes, &kms, &user)
                .await
                .map_err(CryptoApiError::from)?;
        owm.attributes()
            .get_link(LinkType::PublicKeyLink)
            .map_or_else(|| body.kid.clone(), |l| l.to_string())
    };
    let protected_header = json!({
        "alg": body.alg,
        "kid": signing_kid,
    });
    let protected_json = protected_header.to_string();
    let protected_b64 = b64_encode(protected_json.as_bytes());

    b64_decode("data", &body.data)?;
    let payload_b64 = body.data.as_str();

    // RFC 7515 §2: signing_input = ASCII(protected_b64 + "." + payload_b64)
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signing_input_bytes = signing_input.as_bytes().to_vec();

    let kmip_params = jose_to_kmip_params(&body.alg, None)?;
    let sign_req = KmipSign {
        unique_identifier: Some(UniqueIdentifier::TextString(body.kid.clone())),
        cryptographic_parameters: Some(kmip_params),
        data: Some(Zeroizing::new(signing_input_bytes)),
        ..Default::default()
    };

    let resp = kms
        .sign(sign_req, &user)
        .await
        .map_err(CryptoApiError::from)?;

    let signature_bytes = resp.signature_data.ok_or_else(|| {
        CryptoApiError::InternalError("Sign response missing signature_data".to_owned())
    })?;

    Ok(Json(CryptoSignResponse {
        protected: protected_b64,
        signature: b64_encode(&signature_bytes),
    }))
}
