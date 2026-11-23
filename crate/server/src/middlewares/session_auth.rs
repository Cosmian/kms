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

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header::{HeaderValue, SET_COOKIE},
    middleware::Next,
    web,
};
use cosmian_logger::{debug, trace, warn};
use futures::{
    Future,
    future::{Ready, ok},
};

use crate::middlewares::{
    AuthMethod, AuthenticatedUser, UiSessionCookie, is_not_forgeable_cross_origin,
    reject_reserved_service_identity,
};

/// CSRF guard for scopes whose JSON extractor accepts any Content-Type (the Vault KV scopes:
/// Vault/`bao` clients omit it). A mutation authenticated by the ambient session cookie must
/// carry a Content-Type a cross-origin page cannot send without a CORS preflight; bearer,
/// token and certificate callers are unaffected. Wrap it inside the authentication stack so
/// that [`SessionAuth`] has already run.
pub(crate) async fn reject_forgeable_session_mutation<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    let session_authenticated = req
        .extensions()
        .get::<AuthenticatedUser>()
        .is_some_and(|user| user.auth_method == AuthMethod::Session);
    if session_authenticated && !is_not_forgeable_cross_origin(&req) {
        warn!(
            "Session: refusing a cookie-authenticated {} without a JSON Content-Type",
            req.method()
        );
        let response = HttpResponse::UnsupportedMediaType().json(serde_json::json!({
            "errors": ["a session-authenticated write requires `Content-Type: application/json`"]
        }));
        return Ok(req.into_response(response).map_into_right_body());
    }
    Ok(next.call(req).await?.map_into_left_body())
}

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

        // No codec registered (bare test apps): no session, nothing is authenticated.
        let codec = req.app_data::<web::Data<UiSessionCookie>>().cloned();
        let mut purge = None;
        if let Some(username) = codec
            .as_ref()
            .and_then(|codec| codec.read(req.headers()))
            .and_then(|session| session.user_id)
        {
            debug!("Session: authenticated user '{username}'");
            match reject_reserved_service_identity(&username) {
                Ok(()) => {
                    req.extensions_mut().insert(AuthenticatedUser {
                        username,
                        auth_method: AuthMethod::Session,
                    });
                }
                Err(error) => {
                    warn!(
                        "Session: rejecting reserved service identity from stored \
                         session user_id: {error}"
                    );
                    purge = codec.map(|codec| codec.removal_cookie());
                }
            }
        } else {
            trace!("Session: no user_id in session, passing through");
        }

        Box::pin(async move {
            let mut res = service.call(req).await?;
            if let Some(removal) = purge {
                res.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&removal)
                        .map_err(actix_web::error::ErrorInternalServerError)?,
                );
            }
            Ok(res.map_into_left_body())
        })
    }
}
