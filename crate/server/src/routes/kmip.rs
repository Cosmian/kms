use std::sync::Arc;

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::{
    kmip_messages::Message,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use josekit::jwe::{alg::ecdh_es::EcdhEsJweAlgorithm, deserialize_compact};
use tracing::info;

use crate::{
    core::{operations::dispatch, KMS},
    database::KMSServer,
    error::KmsError,
    result::KResult,
};

/// Generate KMIP generic key pair
#[post("/kmip/2_1")]
pub async fn kmip(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<TTLV>> {
    let ttlv = match serde_json::from_str::<TTLV>(&body) {
        Ok(ttlv) => ttlv,
        Err(_) => {
            let key = kms
                .params
                .jwe_config
                .jwk_private_key
                .as_ref()
                .ok_or_else(|| {
                    KmsError::NotSupported("this server doesn't support JWE encryption".to_string())
                })?;

            let decrypter = EcdhEsJweAlgorithm::EcdhEs
                .decrypter_from_jwk(key)
                .map_err(|err| {
                    KmsError::ServerError(format!(
                        "Fail to create decrypter from JWE private key ({err})."
                    ))
                })?;
            let payload = deserialize_compact(&body, &decrypter).map_err(|err| {
                KmsError::InvalidRequest(format!("Fail to decrypt with JWE private key ({err})."))
            })?;

            serde_json::from_slice::<TTLV>(&payload.0)?
        }
    };

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    info!("POST /kmip. Request: {:?} {}", ttlv.tag.as_str(), user);

    let ttlv = handle_ttlv(&kms, &ttlv, &user, database_params.as_ref()).await?;
    Ok(Json(ttlv))
}

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation`s serialized in a single KMIP `Message`
pub async fn handle_ttlv(
    kms: &KMS,
    ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    match ttlv.tag.as_str() {
        "Message" => {
            let req = from_ttlv::<Message>(ttlv)?;
            let resp = kms.message(req, user, database_params).await?;
            Ok(to_ttlv(&resp)?)
        }
        _ => {
            let operation = dispatch(kms, ttlv, user, database_params).await?;
            Ok(to_ttlv(&operation)?)
        }
    }
}
