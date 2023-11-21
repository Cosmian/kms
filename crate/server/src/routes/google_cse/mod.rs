use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use serde::Serialize;
use tracing::{debug, info, trace};

use crate::{error::KmsError, result::KResult, KMSServer};

mod jwt;
mod operations;

pub use jwt::{jwt_authorization_config, GoogleCseConfig};

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
