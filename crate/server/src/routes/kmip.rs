use std::sync::Arc;

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::ttlv::{serializer::to_ttlv, TTLV};
use josekit::jwe::{alg::ecdh_es::EcdhEsJweAlgorithm, deserialize_compact};
use tracing::info;

use crate::{core::operations::dispatch, database::KMSServer, error::KmsError, result::KResult};

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

    let operation = dispatch(&kms, &ttlv, &user, database_params.as_ref()).await?;
    let ttlv = to_ttlv(&operation)?;
    Ok(Json(ttlv))
}
