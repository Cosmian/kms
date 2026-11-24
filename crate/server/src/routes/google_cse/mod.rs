use core::fmt;
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, ResponseError, get, post,
    web::{Data, Json},
};
use cosmian_logger::{debug, info, trace};
use serde::{Deserialize, Serialize};

use crate::{core::KMS, error::KmsError, result::KResult};

mod jwt;
pub mod operations;

pub use jwt::{
    GoogleCseConfig, PrivilegedCaller, jwt_authorization_config, list_jwks_uri,
    list_jwt_configurations, validate_cse_authentication_token, validate_cse_privileged_token,
};

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
    fn from(mut e: CseErrorReply) -> Self {
        debug!("CSE Error: {:?}", e);
        match e.code {
            400 => Self::BadRequest().json(e),
            401 => Self::Unauthorized().json(e),
            403 => Self::Forbidden().json(e),
            404 => Self::NotFound().json(e),
            405 => Self::MethodNotAllowed().json(e),
            422 => Self::UnprocessableEntity().json(e),
            _ => {
                let (mut builder, message) = crate::routes::internal_error(
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                    &e.details,
                );
                e.details = message;
                builder.json(e)
            }
        }
    }
}

/// Builds the full Google CSE KACLS URL using the base KMS public URL.
///
/// This function constructs a URL like `https://<kms_public_url>/google_cse`
/// by retrieving and trimming the `kms_public_url` from the KMS configuration.
///
/// # Arguments
///
/// * `kms` - A reference-counted pointer to the KMS instance containing configuration parameters.
///
/// # Returns
///
/// Returns `Ok(String)` containing the fully constructed Google CSE URL if the `kms_public_url` is set.
///
/// # Errors
///
/// Returns a `KmsError::ServerError` if the `kms_public_url` is not configured (`None`).
pub fn build_google_cse_url(base_url: Option<&str>) -> KResult<String> {
    let base_url = base_url
        .ok_or_else(|| {
            KmsError::ServerError(
                "Google CSE KACLS URL can't be built: missing KMS_PUBLIC_URL".to_owned(),
            )
        })?
        .trim_end_matches('/');

    Ok(format!("{base_url}/google_cse"))
}

/// Get the status for Google CSE and the URL of the deployed KACLS (Key Access Control List Service)
#[get("/status")]
pub(crate) async fn get_status(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
) -> KResult<Json<operations::StatusResponse>> {
    info!("GET /google_cse/status {}", kms.get_user(&req));

    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    Ok(Json(operations::get_status(&google_cse_kacls_url)))
}

/// Expose RSA Public key elements for migration
#[get("/certs")]
pub(crate) async fn certs(kms: Data<Arc<KMS>>) -> KResult<Json<operations::CertsResponse>> {
    info!("GET /certs");

    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    Ok(Json(
        operations::display_rsa_public_key(&kms, &google_cse_kacls_url).await?,
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
    trace!("{info_msg} request received");
    let cse_config = cse_config.into_inner();
    (request, cse_config)
}

/// Turn a CSE operation result into a JSON 200 response or a structured CSE error reply.
fn cse_response<T: Serialize>(result: KResult<T>) -> HttpResponse {
    match result {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => CseErrorReply::from(&e).into(),
    }
}

#[post("/digest")]
pub(crate) async fn digest(
    req_http: HttpRequest,
    request: Json<DigestRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("digest", request, cse_config);
    cse_response(operations::digest(&req_http, request, &cse_config, &kms).await)
}

#[post("/privilegedprivatekeydecrypt")]
pub(crate) async fn privileged_private_key_decrypt(
    req_http: HttpRequest,
    request: Json<PrivilegedPrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) =
        prepare_post_params("privilegedprivatekeydecrypt", request, cse_config);
    cse_response(
        operations::privileged_private_key_decrypt(&req_http, request, &cse_config, &kms).await,
    )
}

#[post("/privilegedunwrap")]
pub(crate) async fn privileged_unwrap(
    req_http: HttpRequest,
    request: Json<PrivilegedUnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privilegedunwrap", request, cse_config);
    cse_response(operations::privileged_unwrap(&req_http, request, &cse_config, &kms).await)
}

#[post("/privilegedwrap")]
pub(crate) async fn privileged_wrap(
    req_http: HttpRequest,
    request: Json<PrivilegedWrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privilegedwrap", request, cse_config);
    cse_response(operations::privileged_wrap(&req_http, request, &cse_config, &kms).await)
}

#[post("/rewrap")]
pub(crate) async fn rewrap(
    req_http: HttpRequest,
    request: Json<RewrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("rewrap", request, cse_config);
    let Some(base_url) = kms.params.kms_public_url.clone() else {
        return CseErrorReply::from(&KmsError::InvalidRequest(
            "Google CSE KACLS URL can't be built: missing KMS_PUBLIC_URL".to_owned(),
        ))
        .into();
    };

    let google_cse_kacls_url = format!("{base_url}/google_cse");
    cse_response(
        operations::rewrap(&req_http, request, &google_cse_kacls_url, &cse_config, &kms).await,
    )
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
    req_http: HttpRequest,
    request: Json<operations::WrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("wrap", request, cse_config);
    cse_response(operations::wrap(&req_http, request, &cse_config, &kms).await)
}

/// Decrypt the Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/unwrap")]
pub(crate) async fn unwrap(
    req_http: HttpRequest,
    request: Json<operations::UnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("unwrap", request, cse_config);
    cse_response(operations::unwrap(&req_http, request, &cse_config, &kms).await)
}

/// Unwraps a wrapped private key and then signs the digest provided by the client.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-sign)
#[post("/privatekeysign")]
pub(crate) async fn private_key_sign(
    req_http: HttpRequest,
    request: Json<operations::PrivateKeySignRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privatekeysign", request, cse_config);
    cse_response(operations::private_key_sign(&req_http, request, &cse_config, &kms).await)
}

/// Unwraps a wrapped private key and then decrypts the content encryption key that is encrypted to the public key.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/private-key-decrypt)
#[post("/privatekeydecrypt")]
pub(crate) async fn private_key_decrypt(
    req_http: HttpRequest,
    request: Json<operations::PrivateKeyDecryptRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let (request, cse_config) = prepare_post_params("privatekeydecrypt", request, cse_config);
    cse_response(operations::private_key_decrypt(&req_http, request, &cse_config, &kms).await)
}

#[post("/delegate")]
pub(crate) async fn delegate(
    _req_http: HttpRequest,
    _request: Json<WrapPrivateKeyRequest>,
    _cse_config: Data<Option<GoogleCseConfig>>,
    _kms: Data<Arc<KMS>>,
) -> HttpResponse {
    info!("POST /google_cse/delegate: not implemented yet");
    HttpResponse::Ok().finish()
}

#[cfg(test)]
mod tests {
    use actix_web::{body::to_bytes, http::StatusCode};

    use super::{CseErrorReply, HttpResponse, KmsError};

    #[actix_web::test]
    async fn cse_internal_error_hides_details() {
        let reply = CseErrorReply::from(&KmsError::ServerError("secret detail".to_owned()));
        let response = HttpResponse::from(reply);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("x-request-id header")
            .to_owned();
        let body = to_bytes(response.into_body()).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["details"],
            format!("Internal Server Error (request id: {id})")
        );
        assert_eq!(json["message"], "A CSE request to the Cosmian KMS failed");
        assert!(!String::from_utf8_lossy(&body).contains("secret detail"));
    }
}
