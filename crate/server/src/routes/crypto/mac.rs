use std::sync::Arc;

use actix_web::{
    HttpRequest, post,
    web::{Data, Json},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::{MAC, MACVerify},
    kmip_types::{UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::trace;
use serde::Serialize;

use super::{
    CryptoApiError, MacComputeResponse, MacRequest, MacVerifyResponse, b64_decode, b64_encode,
    jose_to_kmip_params,
};
use crate::core::KMS;

/// MAC operation response — either compute or verify result.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum MacResponse {
    Compute(MacComputeResponse),
    Verify(MacVerifyResponse),
}

/// `POST /v1/crypto/mac` — HMAC compute or verify.
///
/// - If `mac` field is absent in the request: compute and return the MAC.
/// - If `mac` field is present in the request: verify and return `valid`.
#[post("/v1/crypto/mac")]
pub(crate) async fn mac(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<MacRequest>,
) -> Result<actix_web::web::Json<MacResponse>, CryptoApiError> {
    let user = kms.get_user(&req);
    let body = body.into_inner();

    trace!(user = user, "POST /v1/crypto/mac kid={}", body.kid);

    let data_bytes = b64_decode("data", &body.data)?;
    let kmip_params = jose_to_kmip_params(&body.alg, None)?;

    if let Some(ref expected_mac_b64) = body.mac {
        let expected_mac_bytes = b64_decode("mac", expected_mac_b64)?;

        let verify_req = MACVerify {
            unique_identifier: UniqueIdentifier::TextString(body.kid.clone()),
            cryptographic_parameters: Some(kmip_params),
            data: data_bytes,
            mac_data: expected_mac_bytes,
        };

        let resp = kms
            .mac_verify(verify_req, &user)
            .await
            .map_err(CryptoApiError::from)?;

        let valid = matches!(resp.validity_indicator, ValidityIndicator::Valid);

        Ok(actix_web::web::Json(MacResponse::Verify(
            MacVerifyResponse {
                kid: body.kid,
                valid,
            },
        )))
    } else {
        let mac_req = MAC {
            unique_identifier: Some(UniqueIdentifier::TextString(body.kid.clone())),
            cryptographic_parameters: Some(kmip_params),
            data: Some(data_bytes),
            ..Default::default()
        };

        let resp = kms
            .mac(mac_req, &user)
            .await
            .map_err(CryptoApiError::from)?;

        let mac_bytes = resp.mac_data.ok_or_else(|| {
            CryptoApiError::InternalError("MAC response missing mac_data".to_owned())
        })?;

        Ok(actix_web::web::Json(MacResponse::Compute(
            MacComputeResponse {
                kid: body.kid,
                mac: b64_encode(&mac_bytes),
            },
        )))
    }
}
