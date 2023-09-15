use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json, Path, Query},
    HttpRequest, HttpResponse, HttpResponseBuilder,
};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_operations::{
        Create, CreateKeyPair, Decrypt, Destroy, Encrypt, Export, Get, GetAttributes, Import,
        Locate, ReKeyKeyPair, Revoke,
    },
    kmip_types::UniqueIdentifier,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use cosmian_kms_utils::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, QuoteParams, SuccessResponse,
    UserAccessResponse,
};
use http::{header, StatusCode};
use josekit::jwe::{alg::ecdh_es::EcdhEsJweAlgorithm, deserialize_compact};
use tracing::{debug, error, info, warn};

use crate::{database::KMSServer, error::KmsError, kms_bail, result::KResult};

impl actix_web::error::ResponseError for KmsError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let message = self.to_string();

        if status_code >= StatusCode::INTERNAL_SERVER_ERROR {
            error!("{status_code} - {message}");
        } else {
            warn!("{status_code} - {message}");
        }

        HttpResponseBuilder::new(status_code)
            .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
            .body(message)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            KmsError::RouteNotFound(_) => StatusCode::NOT_FOUND,

            KmsError::Unauthorized(_) => StatusCode::UNAUTHORIZED,

            KmsError::DatabaseError(_)
            | KmsError::SGXError(_)
            | KmsError::ConversionError(_)
            | KmsError::CryptographicError(_)
            | KmsError::Redis(_)
            | KmsError::Findex(_)
            | KmsError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            KmsError::KmipError(..)
            | KmsError::NotSupported(_)
            | KmsError::UnsupportedProtectionMasks
            | KmsError::UnsupportedPlaceholder
            | KmsError::InconsistentOperation(..)
            | KmsError::InvalidRequest(_)
            | KmsError::ItemNotFound(_)
            | &KmsError::UrlError(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

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

/// List objects owned by the current user
/// i.e. objects for which the user has full access
#[get("/access/owned")]
pub async fn list_owned_objects(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<ObjectOwnedResponse>>> {
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /access/owned {user}");

    let list = kms
        .list_owned_objects(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List objects not owned by the user but for which an access
/// has been obtained by the user
#[get("/access/obtained")]
pub async fn list_access_rights_obtained(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<AccessRightsObtainedResponse>>> {
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /access/granted {user}");

    let list = kms
        .list_access_rights_obtained(&user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// List access rights for an object
#[get("/access/list/{object_id}")]
pub async fn list_accesses(
    req: HttpRequest,
    object_id: Path<(UniqueIdentifier,)>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Vec<UserAccessResponse>>> {
    let object_id = object_id.to_owned().0;
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("GET /accesses/{object_id} {user}");

    let list = kms
        .list_accesses(&object_id, &user, database_params.as_ref())
        .await?;

    Ok(Json(list))
}

/// Grant an access right for an object, given a `userid`
#[post("/access/grant")]
pub async fn grant_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("POST /access/grant {access:?} {user}");

    kms.insert_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access granted on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully added", access.user_id),
    }))
}

/// Revoke an access authorization for an object, given a `userid`
#[post("/access/revoke")]
pub async fn revoke_access(
    req: HttpRequest,
    access: Json<Access>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<SuccessResponse>> {
    let access = access.into_inner();
    let database_params = kms.get_sqlite_enc_secrets(&req)?;
    let user = kms.get_user(req)?;
    info!("POST /access/revoke {access:?} {user}");

    kms.revoke_access(&access, &user, database_params.as_ref())
        .await?;
    debug!(
        "Access revoke on {:?} for {:?} to {}",
        &access.unique_identifier, &access.operation_type, &access.user_id
    );

    Ok(Json(SuccessResponse {
        success: format!("Access for {} successfully deleted", access.user_id),
    }))
}

/// Get the the server X09 certificate in PEM format
#[get("/certificate")]
pub async fn get_certificate(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<Option<String>>> {
    info!("GET /certificate {}", kms.get_user(req)?);
    Ok(Json(kms.get_server_x509_certificate()?))
}

/// Get the quote of the server running inside an enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_quote")]
pub async fn get_enclave_quote(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    let params = Query::<QuoteParams>::from_query(req.query_string())?;
    info!("GET /enclave_quote {}", kms.get_user(req)?);
    Ok(Json(kms.get_quote(&params.nonce)?))
}

/// Get the public key of the  enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_public_key")]
pub async fn get_enclave_public_key(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /enclave_public_key {}", kms.get_user(req)?);
    Ok(Json(kms.get_enclave_public_key()?))
}

/// Get the manifest of the server running inside an enclave
///
/// This service is only enabled when the server is running SGX
#[get("/enclave_manifest")]
pub async fn get_enclave_manifest(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /enclave_manifest {}", kms.get_user(req)?);
    Ok(Json(kms.get_manifest()?))
}

/// Add a new group to the KMS = add a new database
#[post("/new_database")]
pub async fn add_new_database(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<String>> {
    info!("GET /new_database {}", kms.get_user(req)?);
    Ok(Json(kms.add_new_database().await?))
}

/// Get the KMS version
#[get("/version")]
pub async fn get_version(req: HttpRequest, kms: Data<Arc<KMSServer>>) -> KResult<Json<String>> {
    info!("GET /version {}", kms.get_user(req)?);
    Ok(Json(crate_version!().to_string()))
}
