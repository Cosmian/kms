//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.

use std::{
    collections::HashSet,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use crate::core::KMS;
use actix_service::{Service, Transform};
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

use scratchstack_aws_signature::{
    GetSigningKeyResponse, NO_ADDITIONAL_SIGNED_HEADERS, SignatureOptions,
    service_for_signing_key_fn, sigv4_validate_request,
};
use serde::Deserialize;

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
    fn get_signing_key(
        &self,
        access_key_id: &str,
        kms_server: &KMS,
    ) -> Result<GetSigningKeyResponse, BoxError> {
        let user = User::new(PARTITION, ACCOUNT_ID, PATH, USER_NAME)?;
        let secret_key = KSecretKey::from_str(SECRET_KEY).unwrap();
        let signing_key = secret_key.to_ksigning(request.request_date(), REGION, SERVICE);
        Ok(GetSigningKeyResponse::builder()
            .principal(user)
            .signing_key(signing_key)
            .build()?)
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
        let params = kms_server.params.aws_xks_params.clone().expect(
            "AWS XKS Sigv4 middleware should neo be enabled if the aws_xks_params are not set",
        );

        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body_as_bytes = body
                .map(|chunk| chunk.unwrap_or_default())
                .fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(&chunk);
                    acc
                })
                .await;

            // Wrap `get_signing_key` in a `tower::Service`.
            let mut get_signing_key_service = service_for_signing_key_fn(Self::get_signing_key);

            // The headers that _must_ be signed (beyond the default SigV4 headers) for this service.
            // In this case, we're not requiring any additional headers.
            let signed_headers = NO_ADDITIONAL_SIGNED_HEADERS;

            // Signature options for the request. Defaults are typically used, except for S3.
            let signature_options = SignatureOptions::default();

            sigv4_validate_request(
                &parts,
                params.region.as_str(),
                params.service.as_str(),
                get_signing_key_service.as_mut(),
                Utc::now(),
                NO_ADDITIONAL_SIGNED_HEADERS,
                None,
            )
            .await?;

            let sign_request =
                Sigv4Request::from_http_request_parts(&parts, Some(body_as_bytes.clone()));

            // if req.extensions().contains::<AuthenticatedUser>() {
            //     debug!(
            //         "API Token Middleware: An authenticated user was found; there is no need to \
            //          authenticate twice..."
            //     );
            // } else {
            //     match handle_api_token(&kms_server, &req).await {
            //         Ok(()) => {
            //             // Authentication successful, insert the claim into request extensions
            //             // and proceed with the request
            //             req.extensions_mut().insert(AuthenticatedUser {
            //                 username: kms_server.params.default_username.clone(),
            //             });
            //         }
            //         Err(e) => {
            //             debug!("JWT authentication failed: {e:?}");
            //         }
            //     }
            // }
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
