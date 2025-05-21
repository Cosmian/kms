use core::fmt;
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, ResponseError, get, post,
    web::{Data, Json},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

use crate::{core::KMS, error::KmsError, result::KResult};

mod jwt;
pub mod operations;

pub use jwt::{GoogleCseConfig, jwt_authorization_config, list_jwks_uri, list_jwt_configurations};

use self::operations::{
    DigestRequest, PrivilegedPrivateKeyDecryptRequest, PrivilegedUnwrapRequest,
    PrivilegedWrapRequest, RewrapRequest,
};

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
    fn from(e: &KmsError) -> Self {
        Self {
            code: e.status_code().as_u16(),
            message: "A CSE request to the Cosmian KMS failed".to_owned(),
            details: e.to_string(),
        }
    }
}

impl From<CseErrorReply> for HttpResponse {
    fn from(e: CseErrorReply) -> Self {
        debug!("CSE Error: {:?}", e);
        match e.code {
            400 => Self::BadRequest().json(e),
            401 => Self::Unauthorized().json(e),
            403 => Self::Forbidden().json(e),
            404 => Self::NotFound().json(e),
            405 => Self::MethodNotAllowed().json(e),
            422 => Self::UnprocessableEntity().json(e),
            _ => Self::InternalServerError().json(e),
        }
    }
}

/// Get the status for Google CSE and the URL of the deployed KACLS (Key Access Control List Service)
#[get("/status")]
pub(crate) async fn get_status(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<operations::StatusResponse>> {
    info!("GET /google_cse/status {}", kms.get_user(&req));

    let kacls_url = &kms.params.google_cse_kacls_url.clone().ok_or_else(|| {
        KmsError::ServerError(
            "Google CSE KACLS URL is empty. Expected: <https://cse.mydomain.com/google_cse>"
                .to_owned(),
        )
    })?;
    Ok(Json(operations::get_status(kacls_url)))
}

/// Expose RSA Public key elements for migration
#[get("/certs")]
pub(crate) async fn certs(kms: Data<Arc<KMS>>) -> KResult<Json<operations::CertsResponse>> {
    info!("GET /certs");
    let kms = kms.into_inner();
    let kacls_url = &kms.params.google_cse_kacls_url.clone().ok_or_else(|| {
        KmsError::ServerError(
            "Google CSE KACLS URL is empty. Expected: <https://cse.mydomain.com/google_cse>"
                .to_owned(),
        )
    })?;

    Ok(Json(
        operations::display_rsa_public_key(&kms, kacls_url).await?,
    ))
}

fn prepare_post_params<T>(
    info_msg: &str,
    request: Json<T>,
    cse_config: Data<Option<GoogleCseConfig>>,
) -> (T, Arc<Option<GoogleCseConfig>>)
where
    T: fmt::Debug,
{
    info!("POST /google_cse/{info_msg}");
    let request = request.into_inner();
    trace!("{info_msg} request: {:?}", request);
    let cse_config = cse_config.into_inner();
    (request, cse_config)
}

#[post("/digest")]
pub(crate) async fn digest(
    request: Json<DigestRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("digest", request, cse_config);

    match operations::digest(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[post("/privilegedprivatekeydecrypt")]
pub(crate) async fn privileged_private_key_decrypt(
    request: Json<PrivilegedPrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) =
        prepare_post_params("privilegedprivatekeydecrypt", request, cse_config);
    let kms = kms.into_inner();

    match operations::privileged_private_key_decrypt(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[post("/privilegedunwrap")]
pub(crate) async fn privileged_unwrap(
    request: Json<PrivilegedUnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privilegedunwrap", request, cse_config);

    match operations::privileged_unwrap(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[post("/privilegedwrap")]
pub(crate) async fn privileged_wrap(
    request: Json<PrivilegedWrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privilegedwrap", request, cse_config);

    match operations::privileged_wrap(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[post("/rewrap")]
pub(crate) async fn rewrap(
    request: Json<RewrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("rewrap", request, cse_config);
    let Some(kacls_url) = kms.params.google_cse_kacls_url.clone() else {
        return CseErrorReply::from(&KmsError::InvalidRequest(
            "Error getting current KACLS url".to_owned(),
        ))
        .into();
    };

    match operations::rewrap(request, &kacls_url, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[derive(Deserialize, Debug)]
pub struct WrapPrivateKeyRequest {
    pub authentication: String,
    pub perimeter_id: String,
    pub private_key: String,
}
#[post("/wrapprivatekey")]
pub(crate) async fn wrapprivatekey(
    _req_http: HttpRequest,
    _request: Json<WrapPrivateKeyRequest>,
    _cse_config: Data<Option<GoogleCseConfig>>,
    _kms: Data<Arc<KMS>>,
) -> HttpResponse {
    info!("POST /google_cse/wrapprivatekey: not implemented yet");
    HttpResponse::Ok().finish()
}

/// Returns encrypted Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/wrap")]
pub(crate) async fn wrap(
    request: Json<operations::WrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("wrap", request, cse_config);
    let kms = kms.into_inner();

    match operations::wrap(request, &cse_config, &kms).await.map(Json) {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

/// Decrypt the Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/unwrap")]
pub(crate) async fn unwrap(
    request: Json<operations::UnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("unwrap", request, cse_config);
    let kms = kms.into_inner();

    match operations::unwrap(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

/// Unwraps a wrapped private key and then signs the digest provided by the client.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-sign)
#[post("/privatekeysign")]
pub(crate) async fn private_key_sign(
    request: Json<operations::PrivateKeySignRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privatekeysign", request, cse_config);
    let kms = kms.into_inner();

    match operations::private_key_sign(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

/// Unwraps a wrapped private key and then decrypts the content encryption key that is encrypted to the public key.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-decrypt)
#[post("/privatekeydecrypt")]
pub(crate) async fn private_key_decrypt(
    request: Json<operations::PrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privatekeydecrypt", request, cse_config);
    let kms = kms.into_inner();

    match operations::private_key_decrypt(request, &cse_config, &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}
