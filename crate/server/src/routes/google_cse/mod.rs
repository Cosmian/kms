use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest,
};
use tracing::{info, trace};

use crate::{result::KResult, KMSServer};

mod jwt;
mod operations;
pub use jwt::{jwt_authorization_config, GoogleCseConfig};

// {
//   "server_type": "KACLS",
//   "vendor_id": "Test",
//   "version": "demo",
//   "name": "K8 reference",
//   "operations_supported": [
//     "wrap", "unwrap", "privilegedunwrap",
//     "privatekeydecrypt", "privatekeysign", "privilegedprivatekeydecrypt"
//   ]
// }

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
) -> KResult<Json<operations::WrapResponse>> {
    info!("POST /google_cse/wrap");

    let wrap_request = wrap_request.into_inner();
    trace!("wrap_request: {:?}", wrap_request);
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    operations::wrap(req_http, wrap_request, &cse_config, &kms)
        .await
        .map(Json)
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
) -> KResult<Json<operations::UnwrapResponse>> {
    info!("POST /google_cse/unwrap");

    // unwrap all calls parameters
    let unwrap_request = unwrap_request.into_inner();
    trace!("unwrap_request: {:?}", unwrap_request);
    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    operations::unwrap(req_http, unwrap_request, &cse_config, &kms)
        .await
        .map(Json)
}

/// Returns the checksum ("digest") of an unwrapped Data Encryption Key (DEK).
///
/// ```SHA-256("KACLMigration" + resource_identifier + unwrapped_dek)```
///
/// See [doc](https://developers.google.com/workspace/cse/reference/digest)
#[post("/digest")]
pub async fn digest(
    req_http: HttpRequest,
    digest_request: Json<operations::DigestRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<operations::DigestResponse>> {
    info!("POST /google_cse/digest");

    let digest_request = digest_request.into_inner();
    trace!("digest_request: {:?}", digest_request);

    let kms = kms.into_inner();
    let cse_config = cse_config.into_inner();

    operations::digest(req_http, digest_request, &cse_config, &kms)
        .await
        .map(Json)
}
