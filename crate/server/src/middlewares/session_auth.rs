//! Session Authentication Middleware
//!
//! Authenticates UI browser requests using the server-side session cookie set
//! after a successful OIDC or Auth Verifier login. The session stores the
//! authenticated `user_id` (email / subject) and this middleware injects it as
//! `AuthenticatedUser` into the request extensions.
//!
//! This middleware is **always active** — no configuration flag required. When a
//! valid session with a `user_id` is found the request is marked as authenticated
//! and subsequent middlewares (JWT, Cosmian, API-token) are skipped by
//! `EnsureAuth`. When no session is found the middleware passes through silently,
//! allowing other auth methods (Bearer tokens) to take over.

use std::{
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use actix_session::SessionExt as _;
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use cosmian_logger::{debug, trace, warn};
use futures::{
    Future,
    future::{Ready, ok},
};

use crate::middlewares::{AuthMethod, AuthenticatedUser};

/// Middleware factory — registered unconditionally on all UI-facing scopes.
pub(crate) struct SessionAuth;

impl<S, B> Transform<S, ServiceRequest> for SessionAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = SessionAuthMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SessionAuthMiddleware {
            service: Rc::new(service),
        })
    }
}

pub(crate) struct SessionAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SessionAuthMiddleware<S>
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
        trace!("Session Authentication...");
        let service = self.service.clone();

        // Skip if another middleware already authenticated this request.
        if req.extensions().contains::<AuthenticatedUser>() {
            debug!("Session: request already authenticated, skipping");
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        let session = req.get_session();
        match session.get::<String>("user_id") {
            Ok(Some(user_id)) => {
                debug!("Session: authenticated user '{user_id}'");
                let roles = session
                    .get::<Vec<String>>("roles")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let domain = session.get::<String>("domain").ok().flatten();
                req.extensions_mut().insert(AuthenticatedUser {
                    username: user_id.into(),
                    auth_method: AuthMethod::Session,
                    domain,
                    roles,
                });
            }
            Ok(None) => {
                trace!("Session: no user_id in session, passing through");
            }
            Err(e) => {
                // Corrupted or tampered cookie — treat as unauthenticated.
                warn!("Session: failed to read user_id from session: {e:?}");
            }
        }

        Box::pin(async move {
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}
