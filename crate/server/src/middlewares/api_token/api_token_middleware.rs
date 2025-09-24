//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.

use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use cosmian_logger::debug;
use futures::{
    Future,
    future::{Ready, ok},
};

use crate::{
    core::KMS,
    middlewares::{AuthenticatedUser, api_token::api_token_auth::handle_api_token},
};

/// `ApiTokenAuth` is an Actix web middleware that handles API token authentication.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for API token authentication.
#[derive(Clone)]
pub(crate) struct ApiTokenAuth {
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

impl ApiTokenAuth {
    /// Creates a new `ApiTokenAuth` with the given KMS server
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
/// This trait defines how to create a new middleware service (`ApiTokenMiddleware`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for ApiTokenAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = ApiTokenMiddleware<S>;

    /// Creates a new instance of the `ApiTokenMiddleware` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `ApiTokenMiddleware`.
    fn new_transform(&self, service: S) -> Self::Future {
        ok(ApiTokenMiddleware {
            service: Rc::new(service),
            kms_server: self.kms_server.clone(),
        })
    }
}

/// `ApiTokenMiddleware` is the actual middleware service that processes each request
///
/// This middleware validates API tokens for each incoming request.
pub(crate) struct ApiTokenMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

/// Implementation of the Service trait, which defines how requests are processed
///
/// This is where the actual API token authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for ApiTokenMiddleware<S>
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

    /// Processes each request by applying API token authentication
    ///
    /// This uses the existing `manage_api_token_request` function to validate the API token.
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let kms_server = self.kms_server.clone();

        Box::pin(async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "API Token Middleware: An authenticated user was found; there is no need to \
                     authenticate twice..."
                );
            } else {
                match handle_api_token(&kms_server, &req).await {
                    Ok(()) => {
                        // Authentication successful, insert the claim into request extensions
                        // and proceed with the request
                        req.extensions_mut().insert(AuthenticatedUser {
                            username: kms_server.params.default_username.clone(),
                        });
                    }
                    Err(e) => {
                        debug!("JWT authentication failed: {e:?}");
                    }
                }
            }
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
