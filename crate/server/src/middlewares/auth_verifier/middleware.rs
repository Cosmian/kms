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
    session_cookie_realm: Option<Arc<str>>,
}

impl AuthVerifier {
    /// Create a new `AuthVerifier` transformer.
    /// When `jwks_manager` is `None`, the middleware is a no-op (used with `Condition::new(false, …)`).
    /// When `session_cookie_realm` is set, requests without a bearer token may authenticate
    /// with an Auth Verifier `_ea_` session cookie issued for that realm.
    #[must_use]
    pub(crate) const fn new(
        jwks_manager: Option<Arc<JwksManager>>,
        session_cookie_realm: Option<Arc<str>>,
    ) -> Self {
        Self {
            jwks_manager,
            session_cookie_realm,
        }
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
            session_cookie_realm: self.session_cookie_realm.clone(),
        })
    }
}

/// Middleware service — processes each request.
pub(crate) struct AuthVerifierMiddleware<S> {
    service: Rc<S>,
    jwks_manager: Option<Arc<JwksManager>>,
    session_cookie_realm: Option<Arc<str>>,
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
        let session_cookie_realm = self.session_cookie_realm.clone();

        Box::pin(async move {
            // Skip if a previous middleware already authenticated this request.
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "AuthVerifier Middleware: an authenticated user was already found; skipping."
                );
            } else if let Some(ref jwks) = jwks_manager {
                match handle_auth_verifier(jwks, &req, session_cookie_realm.as_deref()).await {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use actix_web::{
        App, HttpMessage, HttpRequest, HttpResponse,
        cookie::Cookie,
        http::{StatusCode, header},
        test, web,
    };

    use super::AuthVerifier;
    use crate::middlewares::{
        AUTH_VERIFIER_SESSION_COOKIE, AuthMethod, AuthenticatedUser,
        auth_verifier_test_helpers::{auth_verifier_token, empty_jwks_manager},
    };

    /// Echoes `<auth method>:<username>`, or 401 when no middleware authenticated the request.
    async fn identity(req: HttpRequest) -> HttpResponse {
        req.extensions().get::<AuthenticatedUser>().map_or_else(
            || HttpResponse::Unauthorized().finish(),
            |user| HttpResponse::Ok().body(format!("{:?}:{}", user.auth_method, user.username)),
        )
    }

    async fn call(realm: Option<&str>, request: test::TestRequest) -> (StatusCode, String) {
        let app = test::init_service(
            App::new()
                .wrap(AuthVerifier::new(
                    Some(empty_jwks_manager().await),
                    realm.map(Arc::from),
                ))
                .route("/", web::get().to(identity)),
        )
        .await;
        let response = test::call_service(&app, request.to_request()).await;
        let status = response.status();
        let body = test::read_body(response).await;
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn with_cookie(token: &str) -> test::TestRequest {
        test::TestRequest::get().cookie(Cookie::new(AUTH_VERIFIER_SESSION_COOKIE, token.to_owned()))
    }

    #[actix_web::test]
    async fn session_cookie_authenticates_when_saml_realm_configured() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let (status, body) = call(Some("kms-saml"), with_cookie(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            format!("{:?}:alice@example.com", AuthMethod::AuthVerifierSession)
        );
    }

    /// Non-regression: without an `auth_verifier_saml_realm`, the `_ea_` cookie is ignored.
    #[actix_web::test]
    async fn session_cookie_ignored_when_saml_realm_not_configured() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let (status, _) = call(None, with_cookie(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn session_cookie_of_another_realm_does_not_authenticate() {
        let token = auth_verifier_token("alice@example.com", Some("other-app"));
        let (status, _) = call(Some("kms-saml"), with_cookie(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// An explicit bearer token takes precedence over an ambient session cookie.
    #[actix_web::test]
    async fn bearer_token_takes_precedence_over_session_cookie() {
        let cookie_token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let bearer_token = auth_verifier_token("bob@example.com", Some("cli-realm"));
        let request = with_cookie(&cookie_token)
            .insert_header((header::AUTHORIZATION, format!("Bearer {bearer_token}")));
        let (status, body) = call(Some("kms-saml"), request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            format!("{:?}:bob@example.com", AuthMethod::AuthVerifierJwt)
        );
    }
}
