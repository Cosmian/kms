//! Authentication Fallback Middleware
//!
//! This middleware ensures some form of authentication is present when a request reaches this point.
//! It provides a fallback mechanism that:
//! - Uses the default username from KMS server parameters if configured
//! - Returns a 401 Unauthorized response if no authentication is configured

use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use futures::{
    Future,
    future::{Ready, ok},
};
use tracing::{debug, error};

use crate::{core::KMS, middlewares::AuthenticatedUser};

/// `EnsureAuth` is an Actix web middleware ensuring some authentication.
///
/// This middleware is used when no other authentication methods are configured. It will:
/// - Return the default username from KMS server parameters if configured
/// - Return a 401 Unauthorized response otherwise
#[derive(Clone)]
pub(crate) struct EnsureAuth {
    /// Reference to the KMS server for accessing server parameters
    kms_server: Arc<KMS>,
    auth_is_configured: bool,
}

impl EnsureAuth {
    /// Creates a new `EnsureAuth` with the given KMS server
    ///
    /// # Parameters
    /// * `kms_server` - The KMS server instance
    #[must_use]
    pub(crate) const fn new(kms_server: Arc<KMS>, auth_is_configured: bool) -> Self {
        Self {
            kms_server,
            auth_is_configured,
        }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`EnsureMiddleware`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for EnsureAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = EnsureMiddleware<S>;

    /// Creates a new instance of the `EnsureMiddleware` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `EnsureMiddleware`.
    fn new_transform(&self, service: S) -> Self::Future {
        ok(EnsureMiddleware {
            service: Rc::new(service),
            kms_server: self.kms_server.clone(),
            auth_is_configured: self.auth_is_configured,
        })
    }
}

/// `EnsureMiddleware` is the actual middleware service that processes each request
///
/// This middleware examines if the KMS server has a `default_username` configured,
/// and if so, uses it as the authenticated user.
pub(crate) struct EnsureMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Reference to the KMS server for accessing server parameters
    kms_server: Arc<KMS>,
    auth_is_configured: bool,
}

/// Implementation of the Service trait which defines how requests are processed
///
/// This is where the actual fallback authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for EnsureMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    /// Checks if the middleware is ready to process a request
    ///
    /// This forwards the readiness check to the wrapped service.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    /// Handles incoming requests to ensure authentication requirements are met.
    ///
    /// - If the request is already authenticated (contains an `AuthenticatedUser`),
    ///   it passes the request to the next service.
    /// - If any authentication method is configured but not provided,
    ///   responds with 401 Unauthorized.
    /// - If no authentication is configured, it injects the default username (if set)
    ///   as the authenticated user and passes the request to the next service.
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        // Check if another middleware already authenticates the request
        if req.extensions().contains::<AuthenticatedUser>() {
            // Request is already authenticated, so we pass it through
            debug!("Request already authenticated, skipping Ensure Auth middleware");
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        //If any means of authentication is configured (Client certificates, JWT, or API token),
        // fail with 401 Unauthorized
        if self.auth_is_configured {
            error!("Authentication method configured, but no authentication provided");
            return Box::pin(async move {
                Ok(req
                    .into_response(HttpResponse::Unauthorized().body("No authentication provided."))
                    .map_into_right_body())
            });
        }

        // Insert the default username as the authenticated user
        req.extensions_mut().insert(AuthenticatedUser {
            username: self.kms_server.params.default_username.clone(),
        });

        Box::pin(async move {
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
