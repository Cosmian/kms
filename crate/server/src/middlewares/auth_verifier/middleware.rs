//! Auth Verifier Middleware
//!
//! Actix-web transformer + service that wraps the core token validation logic
//! in `token`.  The pattern mirrors `ApiTokenMiddleware`.

use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use cosmian_logger::debug;
use futures::{
    Future,
    future::{Ready, ok},
};

use super::token::handle_auth_verifier;
use crate::middlewares::{AuthenticatedUser, JwksManager};

/// Transformer — registered once during app startup.
#[derive(Clone)]
pub(crate) struct AuthVerifier {
    jwks_manager: Option<Arc<JwksManager>>,
}

impl AuthVerifier {
    /// Create a new `AuthVerifier` transformer.
    /// When `jwks_manager` is `None`, the middleware is a no-op (used with `Condition::new(false, …)`).
    #[must_use]
    pub(crate) const fn new(jwks_manager: Option<Arc<JwksManager>>) -> Self {
        Self { jwks_manager }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthVerifier
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = AuthVerifierMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthVerifierMiddleware {
            service: Rc::new(service),
            jwks_manager: self.jwks_manager.clone(),
        })
    }
}

/// Middleware service — processes each request.
pub(crate) struct AuthVerifierMiddleware<S> {
    service: Rc<S>,
    jwks_manager: Option<Arc<JwksManager>>,
}

impl<S, B> Service<ServiceRequest> for AuthVerifierMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let jwks_manager = self.jwks_manager.clone();

        Box::pin(async move {
            // Skip if a previous middleware already authenticated this request.
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "AuthVerifier Middleware: an authenticated user was already found; skipping."
                );
            } else if let Some(ref jwks) = jwks_manager {
                match handle_auth_verifier(jwks, &req).await {
                    Ok(user) => {
                        debug!(
                            "AuthVerifier Middleware: authenticated user `{}`",
                            user.username
                        );
                        req.extensions_mut().insert(user);
                    }
                    Err(e) => {
                        debug!("AuthVerifier Middleware: authentication failed: {e:?}");
                    }
                }
            }
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
