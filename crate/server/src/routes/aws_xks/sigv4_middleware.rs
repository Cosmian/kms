//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.
//!
//! Authentication: <https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md#authentication>
//! Proxy Impl: <https://github.com/aws-samples/aws-kms-xks-proxy/tree/main>
//! Testing client: <https://github.com/aws-samples/aws-kms-xksproxy-test-client>

use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error,
    body::{BoxBody, EitherBody},
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform},
    error::InternalError,
    http::StatusCode,
};
use chrono::Duration;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::Get,
    kmip_types::{KeyFormatType, UniqueIdentifier},
};
use cosmian_logger::debug;
use futures::{
    Future, StreamExt,
    future::{Ready, err, ok},
};
use scratchstack_aws_signature::{
    Request as Sigv4Request, SigningKey, SigningKeyKind::KSecret, sigv4_verify,
};
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    routes::aws_xks::error::{XksErrorName, XksErrorReply},
};

/// `Sigv4MWare` is an Actix web middleware that handles AWS Signature Version 4 (sigv4) protocol.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for API token authentication.
#[derive(Clone)]
pub struct Sigv4MWare {
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

impl Sigv4MWare {
    /// Creates a new `Sigv4MWare` with the given KMS server
    ///
    /// # Parameters
    /// * `kms_server` - The KMS server instance used for API token validation
    #[must_use]
    pub const fn new(kms_server: Arc<KMS>) -> Self {
        Self { kms_server }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`Sigv4Service`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for Sigv4MWare
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = Sigv4Service<S, B>;

    /// Creates a new instance of the `Sigv4Service` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `Sigv4Service`.
    fn new_transform(&self, service: S) -> Self::Future {
        if self.kms_server.params.aws_xks_params.is_none() {
            tracing::error!(
                "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set"
            );
            return err(());
        }
        ok(Sigv4Service {
            service: Rc::new(service),
            kms_server: self.kms_server.clone(),
        })
    }
}

/// `Sigv4Service` is the actual middleware service that processes each request
///
/// This middleware validates API tokens for each incoming request.
pub struct Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

/// Implementation of the Service trait, which defines how requests are processed
///
/// This is where the actual API token authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    /// Checks if the middleware is ready to process a request
    ///
    /// This forwards the readiness check to the wrapped service.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    /// Processes each request by checking the signature v4
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let kms_server = self.kms_server.clone();

        Box::pin(async move {
            let params = kms_server.params.aws_xks_params.clone().ok_or_else(||
                actix_web::error::ErrorInternalServerError(
                    "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set",
                )
            )?;
            let access_key_id = params.sigv4_access_key_id;
            let access_key = params.sigv4_secret_access_key;

            let (actix_web_http_request, body): (actix_web::HttpRequest, actix_web::dev::Payload) =
                req.into_parts();

            let body_as_bytes = body
                .map(Result::unwrap_or_default)
                .fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(&chunk);
                    acc
                })
                .await;

            let http_request = to_http_request(&actix_web_http_request, &body_as_bytes)?;
            let (parts, body) = http_request.into_parts();
            // let body_as_bytes: Option<Bytes> = hyper::body::to_bytes(body).await.ok();
            // let body_as_vec_u8: Option<Vec<u8>> =
            //     body_as_bytes.as_ref().map(|bytes| bytes.to_vec());
            let sigv4_req = Sigv4Request::from_http_request_parts(&parts, Some(body));
            let gsk_req = sigv4_req
                .to_get_signing_key_request(
                    KSecret,
                    params.region.as_str(),
                    params.service.as_str(),
                )
                .map_err(|signature_err| {
                    actix_web::error::ErrorUnauthorized(signature_err.to_string())
                })?;

            if access_key_id != gsk_req.access_key {
                let err: Self::Error = XksErrorReply {
                    errorName: XksErrorName::AuthenticationFailedException,
                    errorMessage: Some(format!("Access key id {} not found", gsk_req.access_key)),
                }
                .into();
                return Err(err);
            }

            let signing_key = SigningKey {
                kind: KSecret,
                key: access_key.as_bytes().to_vec(),
            };
            let allowed_mismatch = Some(Duration::minutes(5));
            if let Err(signature_error) = sigv4_verify(
                &sigv4_req,
                &signing_key,
                allowed_mismatch,
                params.region.as_str(),
                params.service.as_str(),
            ) {
                tracing::warn!("SigV4 failure: {signature_error}");
                let err: Self::Error = XksErrorReply {
                    errorName: XksErrorName::AuthenticationFailedException,
                    errorMessage: Some(format!(
                        "Signature v4 verification failed: {signature_error}",
                    )),
                }
                .into();
                return Err(err);
            }

            // rebuild request with body_as_bytes and forward to next service
            let req =
                ServiceRequest::from_parts(actix_web_http_request, Payload::from(body_as_bytes));
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

fn to_http_request(
    actix_req: &actix_web::HttpRequest,
    body: &[u8],
) -> Result<http::Request<Vec<u8>>, actix_web::error::Error> {
    let method: http::Method = actix_req.method().as_str().parse().map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to parse HTTP method for Sigv4 validation: {e:?}"
        ))
    })?;
    let uri: http::Uri = actix_req.uri().to_string().parse().map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to parse HTTP URI for Sigv4 validation: {e:?}"
        ))
    })?;
    let version: http::Version = match actix_req.version() {
        actix_web::http::Version::HTTP_09 => http::Version::HTTP_09,
        actix_web::http::Version::HTTP_10 => http::Version::HTTP_10,
        actix_web::http::Version::HTTP_2 => http::Version::HTTP_2,
        actix_web::http::Version::HTTP_3 => http::Version::HTTP_3,
        _ => http::Version::HTTP_11,
    };

    let mut http_request_builder = http::request::Builder::new()
        .method(method)
        .uri(uri)
        .version(version);

    // If using the HTTP/2, the host header is missing in the request and must be added manually
    // for the signature to match
    let mut host_header_available = false;
    for (header_name, header_value) in actix_req.headers() {
        if header_name.as_str() == http::header::HOST.as_str() {
            host_header_available = true;
        }
        http_request_builder =
            http_request_builder.header(header_name.as_str(), header_value.as_bytes());
    }
    if !host_header_available {
        debug!(
            "Sigv4 Middleware - Adding missing HOST header: {}",
            actix_req.connection_info().host()
        );
        http_request_builder = http_request_builder.header(
            http::header::HOST,
            actix_req.connection_info().host().as_bytes(),
        );
    }
    // http_request_builder =
    //     http_request_builder.header(http::header::HOST, "localhost:9998".as_bytes());

    let http_request = http_request_builder.body(body.to_vec()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to rebuild request for Sigv4 validation: {e:?}"
        ))
    })?;

    Ok(http_request)
}

/// Retrieves the AWS XKS sigv4 signing key from the KMS server
#[allow(dead_code)]
async fn get_aws_key(
    kms_server: &Arc<KMS>,
    sigv4_access_key_id: &str,
    sigv4_access_key_user: &str,
) -> Result<Zeroizing<Vec<u8>>, actix_web::error::InternalError<String>> {
    kms_server
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(
                    sigv4_access_key_id.to_owned(),
                )),
                key_format_type: Some(KeyFormatType::Raw),
                ..Default::default()
            },
            sigv4_access_key_user,
        )
        .await
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?
        .object
        .key_block()
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key block from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?
        .secret_data_bytes()
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key bytes from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}
