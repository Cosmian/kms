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
use cosmian_aws_structs::health_status::{
    EkmFleetDetails, GetHealthStatusRequest, GetHealthStatusResponse,
};
use tracing::info;

use crate::core::KMS;

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
