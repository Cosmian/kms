//! `GetHealthStatus`
//! ---------------
//! This API serves multiple purposes
//!
//! It is used to ensure that the XKS Proxy base URL (https://!<server>/<path-prefix>/kms/xks/v1)
//! and `SigV4` credentials required to communicate with the proxy are configured correctly in KMS.
//!
//! It is used to ensure that the XKS Proxy is ready to handle
//! other API requests (encrypt/decrypt/getKeyMetadata)
//!
//! It is used to gather information for proactively monitoring availability risks
//! and processing KMS customer requests to raise the Transactions Per Second (TPS) limit
//! on their external key manager.
//!
//! Before returning a successful response (HTTP 200 OK),
//! the XKS Proxy SHOULD verify not only that the external key manager is reachable
//! but is also able to perform cryptographic operations, i.e. the health-check SHOULD be deep
//! rather than shallow.
//!
//! The health check should be implemented such that a successful check provides strong assurance
//! that an encrypt, decrypt or getKeyMetadata request issued immediately
//! after will succeed (except due to authorization checks).
//!
//! The XKS Proxy SHOULD create test keys in the external key manager
//! and invoke cryptographic operations on them as part of the deep Healthcheck.
//!
//! This API MUST be excluded from secondary authorization if the XKS Proxy implements such authorization.
//!
//! HTTP Method: POST
//!
//! API specs: <https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md#gethealthstatus>
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json},
};
use clap::crate_version;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::core::KMS;

/// Request Payload Parameters: The HTTP body of the request contains the requestMetadata.
#[derive(Deserialize, Debug, Serialize)]
#[allow(non_snake_case)]
pub(crate) struct GetHealthStatusRequest {
    pub requestMetadata: RequestMetadata,
}

/// Request Payload Parameters: The HTTP body of the request only contains the requestMetadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) struct RequestMetadata {
    /// This is the requestId of the call made by AWS KMS as part of
    /// a periodic health check which is visible in AWS `CloudTrail`.
    /// The XKS proxy SHOULD log this field to allow a customer to correlate
    /// AWS `CloudTrail` entries with log entries in the XKS Proxy.
    /// This field typically follows the format for UUIDs
    /// but the XKS Proxy MUST treat this as an opaque string and
    /// MUST NOT perform any validation on its structure. This field is REQUIRED.
    pub kmsRequestId: String,

    /// This is the KMS API call that resulted in the XKS Proxy API request.
    /// This field is REQUIRED.
    /// The kmsOperation is set to `CreateCustomKeyStore`, `ConnectCustomKeyStore`,
    /// or `UpdateCustomKeyStore` when the `GetHealthStatus` API is called as part of those KMS APIs.
    /// This field is set to `KmsHealthCheck` when `GetHealthStatus` is called periodically
    /// to get health status for publishing to `CloudWatch` metrics.
    /// The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation
    /// other than those listed for this API call.
    pub kmsOperation: String,
}

// External Key Manager Details
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct EkmFleetDetails {
    /// Unique identifier for the external key manager in the external key manager cluster.
    pub id: String,
    /// Model of the external key manager. This SHOULD include the product name,
    /// version of the hardware and any other information that would be useful
    /// in troubleshooting and estimating TPS capacity.
    pub model: String,
    /// Status of health check on the external key manager from XKS proxy.
    /// The possible statuses are ACTIVE, DEGRADED and UNAVAILABLE. ACTIVE means that
    /// external key manager is healthy, DEGRADED means that external key manager is unhealthy
    /// but can still serve traffic and UNAVAILABLE means that
    /// external key manager is unable to serve traffic.
    pub healthStatus: String,
}

/// Response Payload Parameters: The HTTP body of the response contains
/// the health status of the XKS Proxy and the external key manager.
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub(crate) struct GetHealthStatusResponse {
    ///  Size of XKS proxy fleet. This MUST be an integer greater than zero.
    pub xksProxyFleetSize: u16,
    /// Name of the XKS Proxy vendor, this could be different from the name
    /// of the external key manager vendor.
    /// Both MUST be included even if they are the same.
    pub xksProxyVendor: String,
    /// Model of the XKS Proxy. This SHOULD include the product name and version.
    pub xksProxyModel: String,
    /// Name of the external key manager vendor.
    pub ekmVendor: String,
    /// External Key Manager Details
    pub ekmFleetDetails: Vec<EkmFleetDetails>,
}

#[post("/kms/xks/v1/health")]
pub(crate) async fn get_health_status(
    _req_http: HttpRequest,
    request: Json<GetHealthStatusRequest>,
    _kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let request = request.into_inner();
    info!(
        "POST /aws/kms/xks/v1/health - request id {} - operation {}",
        request.requestMetadata.kmsRequestId, request.requestMetadata.kmsOperation
    );

    let model = format!("Cosmian KMS {}", crate_version!());
    HttpResponse::Ok().json(GetHealthStatusResponse {
        xksProxyFleetSize: 1,
        xksProxyVendor: "Cosmian".to_owned(),
        xksProxyModel: model.clone(),
        ekmVendor: "Cosmian".to_owned(),
        ekmFleetDetails: vec![EkmFleetDetails {
            id: "1".to_owned(),
            model,
            healthStatus: "ACTIVE".to_owned(),
        }],
    })
}
