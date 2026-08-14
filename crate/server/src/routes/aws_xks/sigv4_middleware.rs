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
    GetSigningKeyRequest, GetSigningKeyResponse, KSigningKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, sigv4_validate_request,
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

            let access_key_id_for_svc = access_key_id.clone();
            let access_key_for_svc = access_key.clone();
            let mut get_signing_key_svc = SigningKeyService {
                access_key_id: access_key_id_for_svc,
                access_key: access_key_for_svc,
            };

            if let Err(sigv4_err) = sigv4_validate_request(
                http_request,
                params.region.as_str(),
                params.service.as_str(),
                &mut get_signing_key_svc,
                chrono::Utc::now(),
                &NO_ADDITIONAL_SIGNED_HEADERS,
                SignatureOptions::default(),
            )
            .await
            {
                tracing::warn!("SigV4 failure: {sigv4_err}");
                let err: Self::Error = XksErrorReply {
                    errorName: XksErrorName::AuthenticationFailedException,
                    errorMessage: Some(format!("Signature v4 verification failed: {sigv4_err}")),
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

/// A Tower `Service` that retrieves the `SigV4` signing key for a given access key ID.
///
/// XKS uses a single static key pair; this service validates the access key ID
/// and derives the HMAC signing key from the pre-configured secret.
struct SigningKeyService {
    access_key_id: String,
    access_key: String,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl tower_service::Service<GetSigningKeyRequest> for SigningKeyService {
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send>>;
    type Response = GetSigningKeyResponse;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
        let access_key_id = self.access_key_id.clone();
        let access_key = self.access_key.clone();
        Box::pin(async move {
            if access_key_id != req.access_key() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("Access key id {} not found", req.access_key()),
                    ),
                ));
            }
            let signing_key =
                derive_signing_key(&access_key, req.request_date(), req.region(), req.service())
                    .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
            // XKS does not use IAM principals — build response with signing key only
            GetSigningKeyResponse::builder()
                .signing_key(signing_key)
                .build()
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
        })
    }
}

/// Derives a `SigV4` `K_signing` key, supporting the full XKS-spec secret length range (43–64 chars).
// `KSecretKey::from_str` only accepts exactly M-4 chars (default M=44 → 40 chars); `KSigningKey`
// has no public constructor from raw bytes, so transmute is the only sound approach without
// modifying the upstream scratchstack library.
#[allow(unsafe_code)]
fn derive_signing_key(
    secret: &str,
    date: chrono::NaiveDate,
    region: &str,
    service: &str,
) -> Result<KSigningKey, hmac::digest::InvalidLength> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let hmac_raw = |key: &[u8], msg: &[u8]| -> Result<[u8; 32], hmac::digest::InvalidLength> {
        let mut mac = HmacSha256::new_from_slice(key)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().into())
    };

    let k_secret = format!("AWS4{secret}");
    let date_str = date.format("%Y%m%d").to_string();
    let k_date = hmac_raw(k_secret.as_bytes(), date_str.as_bytes())?;
    let k_region = hmac_raw(&k_date, region.as_bytes())?;
    let k_service = hmac_raw(&k_region, service.as_bytes())?;
    let k_signing = hmac_raw(&k_service, b"aws4_request")?;

    // SAFETY: `KSigningKey` is a single-field newtype over `[u8; 32]` with no padding;
    // its size and alignment are identical to `[u8; 32]`, making this transmute sound.
    Ok(unsafe { std::mem::transmute::<[u8; 32], KSigningKey>(k_signing) })
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
