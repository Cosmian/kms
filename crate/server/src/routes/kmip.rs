use std::sync::Arc;

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::{
    kmip_operations::{
        Certify, Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Export, Get, GetAttributes,
        Import, Locate, ReKeyKeyPair, Revoke,
    },
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use josekit::jwe::{alg::ecdh_es::EcdhEsJweAlgorithm, deserialize_compact};
use tracing::info;

use crate::{database::KMSServer, error::KmsError, kms_bail, result::KResult};

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

    let ttlv_resp = match ttlv.tag.as_str() {
        "Certify" => {
            let req = from_ttlv::<Certify>(&ttlv)?;
            let resp = kms.certify(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Create" => {
            let req = from_ttlv::<Create>(&ttlv)?;
            let resp = kms.create(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "CreateKeyPair" => {
            let req = from_ttlv::<CreateKeyPair>(&ttlv)?;
            let resp = kms
                .create_key_pair(req, &user, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Decrypt" => {
            let req = from_ttlv::<Decrypt>(&ttlv)?;
            let resp = kms.decrypt(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Destroy" => {
            let req = from_ttlv::<Destroy>(&ttlv)?;
            let resp = kms.destroy(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Encrypt" => {
            let req = from_ttlv::<Encrypt>(&ttlv)?;
            let resp = kms.encrypt(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Export" => {
            let req = from_ttlv::<Export>(&ttlv)?;
            let resp = kms.export(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Get" => {
            let req = from_ttlv::<Get>(&ttlv)?;
            let resp = kms.get(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "GetAttributes" => {
            let req = from_ttlv::<GetAttributes>(&ttlv)?;
            let resp = kms
                .get_attributes(req, &user, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Import" => {
            let req = from_ttlv::<Import>(&ttlv)?;
            let resp = kms.import(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "Locate" => {
            let req = from_ttlv::<Locate>(&ttlv)?;
            let resp = kms.locate(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        "ReKeyKeyPair" => {
            let req = from_ttlv::<ReKeyKeyPair>(&ttlv)?;
            let resp = kms
                .rekey_keypair(req, &user, database_params.as_ref())
                .await?;
            to_ttlv(&resp)?
        }
        "Revoke" => {
            let req = from_ttlv::<Revoke>(&ttlv)?;
            let resp = kms.revoke(req, &user, database_params.as_ref()).await?;
            to_ttlv(&resp)?
        }
        x => kms_bail!(KmsError::RouteNotFound(format!("Operation: {x}"))),
    };
    Ok(Json(ttlv_resp))
}
