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
        // The cookie to send back: a removal, or the refreshed cookie of a session in use.
        let mut set_cookie = None;
        if let Some((username, refreshed)) = codec
            .as_ref()
            .and_then(|codec| codec.read_with_refresh(req.headers()))
            .and_then(|(session, refreshed)| Some((session.user_id?, refreshed)))
        {
            debug!("Session: authenticated user '{username}'");
            match reject_reserved_service_identity(&username) {
                Ok(()) => {
                    req.extensions_mut().insert(AuthenticatedUser {
                        username,
                        auth_method: AuthMethod::Session,
                    });
                    set_cookie = refreshed;
                }
                Err(error) => {
                    warn!(
                        "Session: rejecting reserved service identity from stored \
                         session user_id: {error}"
                    );
                    set_cookie = codec.map(|codec| codec.removal_cookie());
                }
            }
        } else {
            trace!("Session: no user_id in session, passing through");
        }

        Box::pin(async move {
            let mut res = service.call(req).await?;
            if let Some(cookie) = set_cookie {
                res.headers_mut().append(
                    SET_COOKIE,
                    HeaderValue::from_str(&cookie)
                        .map_err(actix_web::error::ErrorInternalServerError)?,
                );
            }
            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App, HttpMessage, HttpRequest, HttpResponse,
        http::{StatusCode, header},
        test, web,
    };

    use super::SessionAuth;
    use crate::{
        middlewares::{
            AuthenticatedUser, UiSession, UiSessionCookie, UserId, test_session_cookie_pair,
            test_ui_session_cookie,
        },
        routes::aws_xks::AWS_XKS_SERVICE_USER,
    };

    /// Echoes the user injected by `SessionAuth`, or `anonymous`.
    async fn who(req: HttpRequest) -> HttpResponse {
        let user = req
            .extensions()
            .get::<AuthenticatedUser>()
            .map_or_else(|| "anonymous".to_owned(), |u| u.username.to_string());
        HttpResponse::Ok().body(user)
    }

    /// Calls `GET /` through `SessionAuth`; the request carries a session cookie of `user`.
    /// Returns the echoed user and the `Set-Cookie` headers.
    async fn call(user: Option<&str>, codec: Option<UiSessionCookie>) -> (String, Vec<String>) {
        let cookie = user.map(|user| {
            let session = UiSession {
                user_id: Some(UserId::from(user)),
                ..UiSession::default()
            };
            let set_cookie = test_ui_session_cookie()
                .set_cookie(&session)
                .expect("session cookie");
            set_cookie.split(';').next().expect("name=value").to_owned()
        });
        let mut app = App::new();
        if let Some(codec) = codec {
            app = app.app_data(web::Data::new(codec));
        }
        let app = test::init_service(app.wrap(SessionAuth).route("/", web::get().to(who))).await;
        let mut request = test::TestRequest::get().uri("/");
        if let Some(cookie) = cookie {
            request = request.insert_header((header::COOKIE, cookie));
        }
        let response = test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect();
        let body = test::read_body(response).await;
        (String::from_utf8_lossy(&body).into_owned(), set_cookies)
    }

    #[actix_web::test]
    async fn sealed_session_cookie_authenticates() {
        let (user, set_cookies) =
            call(Some("alice@example.com"), Some(test_ui_session_cookie())).await;
        assert_eq!(user, "alice@example.com");
        assert_eq!(set_cookies, Vec::<String>::new());
    }

    #[actix_web::test]
    async fn reserved_identity_is_refused_and_its_cookie_removed() {
        let (user, set_cookies) =
            call(Some(AWS_XKS_SERVICE_USER), Some(test_ui_session_cookie())).await;
        assert_eq!(user, "anonymous");
        assert!(
            set_cookies
                .iter()
                .any(|c| c.starts_with("auth_session=;") && c.contains("Max-Age=0")),
            "{set_cookies:?}"
        );
    }

    #[actix_web::test]
    async fn cookie_sealed_under_another_key_does_not_authenticate() {
        let other = UiSessionCookie::new(zeroize::Zeroizing::new([0x24; 32]), false);
        let (user, _) = call(Some("alice@example.com"), Some(other)).await;
        assert_eq!(user, "anonymous");
    }

    #[actix_web::test]
    async fn without_a_registered_codec_nothing_is_authenticated() {
        let (user, _) = call(Some("alice@example.com"), None).await;
        assert_eq!(user, "anonymous");
    }

    #[actix_web::test]
    async fn revoked_session_cookie_no_longer_authenticates() {
        let codec = web::Data::new(test_ui_session_cookie());
        let cookie = test_session_cookie_pair(&codec, "alice@example.com");
        let app = test::init_service(
            App::new()
                .app_data(codec.clone())
                .wrap(SessionAuth)
                .route("/", web::get().to(who)),
        )
        .await;
        let request = || {
            test::TestRequest::get()
                .uri("/")
                .insert_header((header::COOKIE, cookie.clone()))
                .to_request()
        };

        let body = test::call_and_read_body(&app, request()).await;
        assert_eq!(body, "alice@example.com");

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_str(&cookie).expect("header"),
        );
        codec.revoke(&headers);

        let body = test::call_and_read_body(&app, request()).await;
        assert_eq!(body, "anonymous");
    }
}
