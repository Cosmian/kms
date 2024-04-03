use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

use crate::{error::KmsError, result::KResult, KMSServer};

mod jwt;
pub mod operations;

pub use jwt::{jwt_authorization_config, list_jwks_uri, GoogleCseConfig};

/// Error reply for Google CSE
///
/// see: <https://developers.google.com/workspace/cse/reference/structured-errors?hl=en>
#[derive(Serialize, Debug)]
struct CseErrorReply {
    code: u16,
    message: String,
    details: String,
}

impl CseErrorReply {
    fn from(e: KmsError) -> Self {
        Self {
            code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "A CSE request to the Cosmian KMS failed".to_string(),
            details: e.to_string(),
        }
    }
}

impl From<CseErrorReply> for HttpResponse {
    fn from(e: CseErrorReply) -> Self {
        debug!("CSE Error: {:?}", e);
        HttpResponse::InternalServerError().json(e)
    }
}

/// Get the status for Google CSE
#[get("/status")]
pub async fn get_status(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<operations::StatusResponse>> {
    info!("GET /google_cse/status {}", kms.get_user(req)?);
    Ok(Json(operations::get_status()))
}

// TODO
#[derive(Deserialize, Debug)]
struct DigestRequest {
    authorization: String,
    reason: String,
    wrapped_key: String,
}
#[post("/digest")]
pub async fn digest(
    req_http: HttpRequest,
    request: Json<DigestRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/digest");
    todo!();
}

#[derive(Deserialize, Debug)]
struct PrivilegedPrivateKeyDecryptRequest {
    authentication: String,
    algorithm: String,
    encrypted_data_encryption_key: String,
    rsa_oaep_label: String,
    reason: String,
    spki_hash: String,
    spki_hash_algorithm: String,
    wrapped_private_key: String,
}
#[post("/privilegedprivatekeydecrypt")]
pub async fn privilegedprivatekeydecrypt(
    req_http: HttpRequest,
    request: Json<PrivilegedPrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/privilegedprivatekeydecrypt");
    todo!();
}

#[derive(Deserialize, Debug)]
struct PrivilegedUnwrapRequest {
    authentication: String,
    reason: String,
    resource_name: String,
    wrapped_key: String,
}
#[post("/privilegedunwrap")]
pub async fn privilegedunwrap(
    req_http: HttpRequest,
    request: Json<PrivilegedUnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/privilegedunwrap");
    todo!();
}

#[derive(Deserialize, Debug)]
struct PrivilegedWrapRequest {
    authentication: String,
    key: String,
    perimeter_id: String,
    reason: String,
    resource_name: String,
}
#[post("/privilegedwrap")]
pub async fn privilegedwrap(
    req_http: HttpRequest,
    request: Json<PrivilegedWrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/privilegedwrap");
    todo!();
}

#[derive(Deserialize, Debug)]
struct RewrapRequest {
    authorization: String,
    original_kacls_url: String,
    reason: String,
    wrapped_key: String,
}
#[post("/rewrap")]
pub async fn rewrap(
    req_http: HttpRequest,
    request: Json<RewrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/rewrap");
    todo!();
}

#[derive(Deserialize, Debug)]
struct WrapPrivateKeyRequest {
    authentication: String,
    perimeter_id: String,
    private_key: String,
}
#[post("/wrapprivatekey")]
pub async fn wrapprivatekey(
    req_http: HttpRequest,
    request: Json<WrapPrivateKeyRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/wrapprivatekey");
    todo!();
}

/// Returns encrypted Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/wrap")]
pub async fn wrap(
    req_http: HttpRequest,
    wrap_request: Json<operations::WrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/wrap");

    let wrap_request = wrap_request.into_inner();
    trace!("wrap_request: {:?}", wrap_request);
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    match operations::wrap(req_http, wrap_request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(wrap_response) => HttpResponse::Ok().json(wrap_response),
        Err(e) => CseErrorReply::from(e).into(),
    }
}

/// Decrypt the Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/unwrap")]
pub async fn unwrap(
    req_http: HttpRequest,
    unwrap_request: Json<operations::UnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/unwrap");

    // unwrap all calls parameters
    let unwrap_request = unwrap_request.into_inner();
    trace!("unwrap_request: {:?}", unwrap_request);
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    match operations::unwrap(req_http, unwrap_request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(wrap_response) => HttpResponse::Ok().json(wrap_response),
        Err(e) => CseErrorReply::from(e).into(),
    }
}

/// Unwraps a wrapped private key and then signs the digest provided by the client.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-sign)
#[post("/privatekeysign")]
pub async fn private_key_sign(
    req_http: HttpRequest,
    private_key_sign_request: Json<operations::PrivateKeySignRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/privatekeysign");

    // unwrap all calls parameters
    let private_key_sign_request = private_key_sign_request.into_inner();
    trace!("private_key_sign_request: {private_key_sign_request:?}");
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    match operations::private_key_sign(req_http, private_key_sign_request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(sign_response) => HttpResponse::Ok().json(sign_response),
        Err(e) => CseErrorReply::from(e).into(),
    }
}

/// Unwraps a wrapped private key and then decrypts the content encryption key that is encrypted to the public key.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-decrypt)
#[post("/privatekeydecrypt")]
pub async fn private_key_decrypt(
    req_http: HttpRequest,
    decrypt_request: Json<operations::PrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    info!("POST /google_cse/privatekeydecrypt");

    // unwrap all calls parameters
    let decrypt_request = decrypt_request.into_inner();
    trace!("decrypt_request: {decrypt_request:?}");
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    match operations::private_key_decrypt(req_http, decrypt_request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(decrypt_response) => HttpResponse::Ok().json(decrypt_response),
        Err(e) => CseErrorReply::from(e).into(),
    }
}
