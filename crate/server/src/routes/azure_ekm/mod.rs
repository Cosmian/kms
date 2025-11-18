#!allow(dead_code, unused_imports)]
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json, Path, Query},
};
use cosmian_logger::{debug, info, trace};
use serde::{Deserialize, Serialize};

use crate::{
    core::KMS, error::KmsError, result::KResult, routes::azure_ekm::error::AzureEkmErrorReply,
};

pub(crate) mod error;

/// List of API versions supported by this implementation
pub(crate) const SUPPORTED_API_VERSIONS: [&str; 1] = [
    "0.1-preview",
    // Add future versions here.
];

pub(crate) const HIGHEST_API_VERSION: &str = "0.1-preview";

pub(crate) fn is_api_version_supported(version: &str) -> bool {
    SUPPORTED_API_VERSIONS.contains(&version)
}

/// Validate API version for all requests
fn validate_api_version(version: &str) -> Result<(), AzureEkmErrorReply> {
    if !SUPPORTED_API_VERSIONS.contains(&version) {
        return Err(AzureEkmErrorReply {
            code: "UnsupportedApiVersion".to_string(),
            message: format!(
                "API version '{}' not supported. Supported: {:?}",
                version, SUPPORTED_API_VERSIONS
            ),
        });
    }
    Ok(())
}
#[derive(Debug, Deserialize)]
pub(crate) struct AzureEkmQueryParams {
    #[serde(rename = "api-version")]
    pub(crate) api_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RequestContext {
    request_id: Option<String>,
    correlation_id: String,
    pool_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProxyInfoRequest {
    request_context: RequestContext,
}

// Post request handlers below
#[post("/info")]
pub(crate) async fn get_proxy_info(
    req: HttpRequest,
    query: Query<AzureEkmQueryParams>,
    request: Json<ProxyInfoRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    info!(
        "POST /ekm/info api-version={} user={}",
        query.api_version,
        kms.get_user(&req)
    );
    trace!("Request: {:?}", request);

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }

    match operations::get_proxy_info(request.into_inner(), &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => AzureEkmErrorReply::from(&e).into(),
    }
}

struct KeyMetadataRequest {
    // TODO: stub
}

#[post("/{key_name}/metadata")]
pub(crate) async fn get_key_metadata(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<KeyMetadataRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    info!(
        "POST /ekm/{}/metadata api-version={} user={}",
        key_name,
        query.api_version,
        kms.get_user(&req)
    );

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    match operations::get_key_metadata(&key_name, request.into_inner(), &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => AzureEkmErrorReply::from(&e).into(),
    }
}

struct WrapKeyRequest {
    // TODO: stub
}

#[post("/{key_name}/wrapkey")]
pub(crate) async fn wrap_key(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<WrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    info!(
        "POST /ekm/{}/wrapkey alg={} api-version={} user={}",
        key_name,
        request.alg,
        query.api_version,
        kms.get_user(&req)
    );

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    match operations::wrap_key(&key_name, request.into_inner(), &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => AzureEkmErrorReply::from(&e).into(),
    }
}

struct UnwrapKeyRequest {
    // TODO: stub
}

#[post("/{key_name}/unwrapkey")]
pub(crate) async fn unwrap_key(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<UnwrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    info!(
        "POST /ekm/{}/unwrapkey alg={} api-version={} user={}",
        key_name,
        request.alg,
        query.api_version,
        kms.get_user(&req)
    );

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    if let Err(e) = validate_key_name(&key_name) {
        return e.into();
    }

    match operations::unwrap_key(&key_name, request.into_inner(), &kms)
        .await
        .map(Json)
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => AzureEkmErrorReply::from(&e).into(),
    }
}
