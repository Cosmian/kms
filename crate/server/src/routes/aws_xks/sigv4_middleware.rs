//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.

use std::{
    collections::HashSet,
    pin::Pin,
    rc::Rc,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use crate::core::KMS;
use actix_service::{Service, Transform};
use actix_web::dev::Payload;
use actix_web::{
    Error,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use chrono::Utc;
use futures::{
    Future, StreamExt,
    future::{Ready, ok},
};
use tower::BoxError;

use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, principal::User, service_for_signing_key_fn, sigv4_validate_request,
};
use serde::Deserialize;

const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const ACCOUNT_ID: &str = "123456789012";
const PARTITION: &str = "aws";
const PATH: &str = "/engineering/";
const REGION: &str = "us-east-1";
const SERVICE: &str = "example";
const USER_NAME: &str = "user";
const USER_ID: &str = "AIDAQXZEAEXAMPLEUSER";

#[derive(Debug, Deserialize, Clone)]
pub struct ExternalKeyStore {
    pub uri_path_prefix: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
    pub xks_key_id_set: HashSet<String>,
}

/// `Sigv4MWare` is an Actix web middleware that handles AWS Signature Version 4 (sigv4) protocol.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for API token authentication.
#[derive(Clone)]
pub(crate) struct Sigv4MWare {
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

impl Sigv4MWare {
    /// Creates a new `Sigv4MWare` with the given KMS server
    ///
    /// # Parameters
    /// * `kms_server` - The KMS server instance used for API token validation
    #[must_use]
    pub(crate) const fn new(kms_server: Arc<KMS>) -> Self {
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
        ok(Sigv4Service {
            service: Rc::new(service),
            kms_server: self.kms_server.clone(),
        })
    }
}

/// `Sigv4Service` is the actual middleware service that processes each request
///
/// This middleware validates API tokens for each incoming request.
pub(crate) struct Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

impl<S, B> Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    /// Extracts the signing key for AWS Sigv4 validation
    ///
    /// This function retrieves the signing key based on the provided access key ID.
    fn get_signing_key_fn(
        &self,
    ) -> impl Fn(
        GetSigningKeyRequest,
    )
        -> Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send>>
    + Send
    + Clone
    + 'static {
        let aws_xks_params = self.kms_server.params.aws_xks_params.as_ref().expect(
            "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set",
        );

        let access_key_id = aws_xks_params.sigv4_access_key_id.clone();
        let secret_key = aws_xks_params.sigv4_secret_access_key.clone();
        //
        let account_id = aws_xks_params.account_id.clone();
        let user_path = aws_xks_params.user_path.clone();
        let user_name = aws_xks_params.user_name.clone();
        let partition = aws_xks_params.partition.clone();

        move |request: GetSigningKeyRequest| {
            Box::pin({
                let access_key_id_ = access_key_id.clone();
                let partition_ = partition.clone();
                let account_id_ = account_id.clone();
                let user_path_ = user_path.clone();
                let user_name_ = user_name.clone();
                let secret_key = secret_key.clone();
                async move {
                    if request.access_key() != access_key_id_.as_str() {
                        return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                            "Access key ID '{}' not found",
                            request.access_key()
                        )) as BoxError);
                    }

                    let user = User::new(
                        partition_.as_str(),
                        account_id_.as_str(),
                        user_path_.as_str(),
                        user_name_.as_str(),
                    )
                    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e) as BoxError)?;

                    let k_secret_key = KSecretKey::from_str(&secret_key).map_err(|e| {
                        Box::<dyn std::error::Error + Send + Sync>::from(e) as BoxError
                    })?;

                    let signing_key = k_secret_key.to_ksigning(
                        request.request_date(),
                        request.region(),
                        request.service(),
                    );

                    let resp = GetSigningKeyResponse::builder()
                        .principal(user)
                        .signing_key(signing_key)
                        .build()
                        .map_err(|e| {
                            Box::<dyn std::error::Error + Send + Sync>::from(e) as BoxError
                        })?;

                    Ok(resp)
                }
            })
        }
    }
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
        let get_signing_key_fn = self.get_signing_key_fn();
        Box::pin(async move {
            let (actix_web_http_request, body): (actix_web::HttpRequest, actix_web::dev::Payload) =
                req.into_parts();
            let body_as_bytes = body
                .map(|chunk| chunk.unwrap_or_default())
                .fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(&chunk);
                    acc
                })
                .await;

            let params = kms_server.params.aws_xks_params.clone().expect(
                "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set",
            );

            // Wrap `get_signing_key` in a `tower::Service`.
            let mut get_signing_key_service = service_for_signing_key_fn(get_signing_key_fn);

            let signature_options = SignatureOptions::default();

            let method: http::Method =
                actix_web_http_request
                    .method()
                    .as_str()
                    .parse()
                    .map_err(|e| {
                        actix_web::error::ErrorBadRequest(format!(
                            "Failed to parse HTTP method for Sigv4 validation: {e:?}"
                        ))
                    })?;
            let uri: http::Uri = actix_web_http_request
                .uri()
                .to_string()
                .parse()
                .map_err(|e| {
                    actix_web::error::ErrorBadRequest(format!(
                        "Failed to parse HTTP URI for Sigv4 validation: {e:?}"
                    ))
                })?;
            let version: http::Version = match actix_web_http_request.version() {
                actix_web::http::Version::HTTP_09 => http::Version::HTTP_09,
                actix_web::http::Version::HTTP_10 => http::Version::HTTP_10,
                actix_web::http::Version::HTTP_11 => http::Version::HTTP_11,
                actix_web::http::Version::HTTP_2 => http::Version::HTTP_2,
                actix_web::http::Version::HTTP_3 => http::Version::HTTP_3,
                _ => http::Version::HTTP_11,
            };
            let mut http_request_builder = http::request::Builder::new()
                .method(method)
                .uri(uri)
                .version(version);

            for (header_name, header_value) in actix_web_http_request.headers().iter() {
                http_request_builder =
                    http_request_builder.header(header_name.as_str(), header_value.as_bytes());
            }

            let http_request = http_request_builder
                .body(body_as_bytes.clone())
                .map_err(|e| {
                    actix_web::error::ErrorBadRequest(format!(
                        "Failed to rebuild request for Sigv4 validation: {e:?}"
                    ))
                })?;

            let (_parts, bytes, sign_auth_response) = sigv4_validate_request(
                http_request,
                params.region.as_str(),
                params.service.as_str(),
                &mut get_signing_key_service,
                Utc::now(),
                &NO_ADDITIONAL_SIGNED_HEADERS,
                signature_options,
            )
            .await
            .map_err(|e| {
                actix_web::error::ErrorUnauthorized(format!("Sigv4 validation failed: {e:?}"))
            })?;

            let _principal = sign_auth_response.principal();
            // rebuild request with body_as_bytes and forward to next service
            let req = ServiceRequest::from_parts(actix_web_http_request, Payload::from(bytes));
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
