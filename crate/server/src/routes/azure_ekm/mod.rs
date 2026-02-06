use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json, Path, Query},
};
use cosmian_logger::{info, trace, warn};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

use crate::{
    core::KMS,
    routes::azure_ekm::{
        error::AzureEkmErrorReply,
        handlers::{get_key_metadata_handler, unwrap_key_handler, wrap_key_handler},
        models::{
            KeyMetadataRequest, ProxyInfoRequest, ProxyInfoResponse, UnwrapKeyRequest,
            WrapKeyRequest,
        },
    },
};

pub(crate) mod error;
pub(crate) mod handlers;
pub(crate) mod models;

/// The proxy is expected to respond to API calls within 250 milliseconds. If Managed HSM
/// does not receive a response within this period, it will time out.
/// This timeout is only set on the wrap/unwrap endpoints, since they can take time, in order to avoid
/// wasteful computing.
const AZURE_EKM_TIMEOUT_MS: u64 = 250;

/// List of API versions supported by this implementation
pub(crate) const SUPPORTED_API_VERSIONS: [&str; 1] = [
    "0.1-preview",
    // Add future versions here, in order.
];

/// Validate API version for all requests
fn validate_api_version(version: &str) -> Result<(), AzureEkmErrorReply> {
    if !SUPPORTED_API_VERSIONS.contains(&version) {
        return Err(AzureEkmErrorReply::unsupported_api_version(version));
    }
    Ok(())
}

fn validate_key_name(key_name: &str) -> Result<(), AzureEkmErrorReply> {
    if key_name.is_empty() || key_name.len() > 127 {
        return Err(AzureEkmErrorReply::invalid_request(
            "Key name length must be between 1 and 127 characters",
        ));
    }

    // Only a-z, A-Z, 0-9, - allowed
    if !key_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(AzureEkmErrorReply::invalid_request(
            "Key name contains illegal characters. Only a-z, A-Z, 0-9, and '-' are allowed.",
        ));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct AzureEkmQueryParams {
    #[serde(rename = "api-version")]
    pub(crate) api_version: String,
}

// Post request handlers below. The request being trivial, it also directly handles its request.
#[post("/info")]
pub(crate) async fn get_proxy_info(
    http_req: HttpRequest,
    query: Query<AzureEkmQueryParams>,
    body: Json<ProxyInfoRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    info!(
        "POST /ekm/info api-version={} user={}",
        query.api_version,
        kms.get_user(&http_req)
    );
    trace!("Request: {:?}", body.into_inner());

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    let conf = kms.params.azure_ekm.clone(); // it's an Arc, so cheap clone

    HttpResponse::Ok().json(ProxyInfoResponse {
        api_version: query.api_version.clone(),
        proxy_vendor: conf.azure_ekm_proxy_vendor,
        proxy_name: conf.azure_ekm_proxy_name,
        ekm_vendor: conf.azure_ekm_ekm_vendor,
        ekm_product: conf.azure_ekm_ekm_product,
    })
}

const SUPPORTED_RSA_LENGTHS: [i32; 3] = [2048, 3072, 4096]; // the KMS key lengths are i32

#[post("/{key_name}/metadata")]
pub(crate) async fn get_key_metadata(
    http_req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    body: Json<KeyMetadataRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&http_req);

    info!(
        "POST /ekm/{}/metadata api-version={} user={}",
        key_name, query.api_version, user,
    );
    trace!("Request: {:?}", body.0);

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    match get_key_metadata_handler(key_name, user, kms).await {
        Ok(response) => response,
        Err(e) => AzureEkmErrorReply::from(e).into(),
    }
}

#[post("/{key_name}/wrapkey")]
pub(crate) async fn wrap_key(
    http_req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    body: Json<WrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&http_req);

    info!(
        "POST /ekm/{}/wrapkey alg={:?} api-version={} user={}",
        key_name, body.alg, query.api_version, user
    );
    trace!("Request: {:?}", body.0);

    // Validate API version
    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    (timeout(Duration::from_millis(AZURE_EKM_TIMEOUT_MS), async {
        match wrap_key_handler(&kms, &key_name, &user, body.into_inner()).await {
            Ok(response) => HttpResponse::Ok().json(response),
            Err(e) => e.into(),
        }
    })
    .await)
        .unwrap_or_else(|_| {
            warn!("Azure EKM /{}/wrapkey request timeout", key_name);
            AzureEkmErrorReply::internal_error(
                "Request timeout: operation exceeded HSM timeout delay, aborting.",
            )
            .into()
        })
}

#[post("/{key_name}/unwrapkey")]
pub(crate) async fn unwrap_key(
    http_req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    body: Json<UnwrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&http_req);

    info!(
        "POST /ekm/{}/unwrapkey alg={:?} api-version={} user={}",
        key_name, body.alg, query.api_version, user
    );
    trace!("Request: {:?}", body.0);

    // Validate API version
    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    (timeout(Duration::from_millis(AZURE_EKM_TIMEOUT_MS), async {
        // Call implementation
        match unwrap_key_handler(&kms, &key_name, &user, body.into_inner()).await {
            Ok(response) => HttpResponse::Ok().json(response),
            Err(e) => e.into(),
        }
    })
    .await)
        .unwrap_or_else(|_| {
            warn!("Azure EKM /{}/wrapkey request timeout", key_name);
            AzureEkmErrorReply::internal_error(
                "Request timeout: operation exceeded HSM timeout delay, aborting.",
            )
            .into()
        })
}
