//! JWT Authentication Middleware
//!
//! This module contains the middleware implementation for JWT-based authentication.
//! It verifies and validates JWT tokens in incoming requests.

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
use futures::{
    Future,
    future::{Ready, ok},
};
use tracing::debug;

use crate::middlewares::{
    AuthenticatedUser,
    jwt::{JwtConfig, jwt_token_auth::handle_jwt},
};

/// `JwtAuth` is an Actix web middleware that handles authentication for the KMS server.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for authentication.
///
/// This middleware handles:
/// - Certificate-based authentication (from an existing `PeerCommonName`)
/// - JWT-based authentication
#[derive(Clone)]
pub(crate) struct JwtAuth {
    /// Optional JWT configuration for JWT-based authentication
    jwt_configurations: Arc<Vec<JwtConfig>>,
}

impl JwtAuth {
    /// Creates a new `JwtAuth` with the optional JWT configurations
    ///
    /// # Parameters
    /// * `jwt_configurations` - Optional JWT configurations for JWT-based authentication
    #[must_use]
    pub(crate) const fn new(jwt_configurations: Arc<Vec<JwtConfig>>) -> Self {
        Self { jwt_configurations }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`JwtAuthMiddleware`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = JwtAuthMiddleware<S>;

    /// Creates a new instance of the `JwtAuthMiddleware` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `JwtAuthMiddleware`.
    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtAuthMiddleware {
            service: Rc::new(service),
            jwt_configurations: self.jwt_configurations.clone(),
        })
    }
}

/// `JwtAuthMiddleware` is the actual middleware service that processes each request
///
/// This middleware examines each request and applies the appropriate authentication logic:
/// - Certificate-based authentication (checked via `PeerCommonName` extension)
/// - JWT-based authentication (if configured)
pub(crate) struct JwtAuthMiddleware<S> {
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Optional JWT configuration for JWT-based authentication
    jwt_configurations: Arc<Vec<JwtConfig>>,
}

/// Implementation of the Service trait, which defines how requests are processed
///
/// This is where the actual authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
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

    /// Processes each request by applying appropriate authentication
    ///
    /// Authentication is performed in the following order:
    /// 1. If certificate authentication is already done (`PeerCommonName` exists), skip further auth
    /// 2. If JWT configurations exist, try JWT-based authentication
    /// 3. If both authentication methods fail, return an unauthorized response
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        // If JWT configurations exist, try JWT-based authentication
        let jwt_configurations = self.jwt_configurations.clone();
        Box::pin(async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "JWT: An authenticated user was found; there is no need to authenticate \
                     twice..."
                );
            } else {
                match handle_jwt(jwt_configurations, &req).await {
                    Ok(auth_claim) => {
                        // Authentication successful, insert the claim into request extensions
                        // and proceed with the request
                        req.extensions_mut().insert(auth_claim);
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
