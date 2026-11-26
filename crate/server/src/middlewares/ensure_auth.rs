//! Authentication Fallback Middleware
//!
//! This middleware ensures some form of authentication is present when a request reaches this point.
//! It provides a fallback mechanism that:
//! - Uses the default username from KMS server parameters if configured
//! - Returns a 401 Unauthorized response if no authentication is configured

use std::sync::Arc;

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::{Next, from_fn},
};
use cosmian_logger::{debug, error, warn};

use crate::{
    core::KMS,
    middlewares::{AuthMethod, AuthenticatedUser, UserId, names_reserved_identity},
};

/// Creates the authentication fallback middleware.
///
/// Ensures that every request reaching this middleware carries an [`AuthenticatedUser`]:
/// - Rejects external identities colliding with `default_username`; otherwise passes them through.
/// - Returns 401 Unauthorized if authentication is required but was not provided.
/// - Injects the server's `default_username` if no authentication is configured at all.
pub(crate) fn ensure_auth_middleware<S, B>(
    kms_server: Arc<KMS>,
    auth_is_configured: bool,
) -> impl Transform<S, ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error, InitError = ()>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    from_fn(move |req: ServiceRequest, next: Next<B>| {
        let kms_server = kms_server.clone();
        async move {
            // Already authenticated by an earlier middleware — pass through.
            if req.extensions().contains::<AuthenticatedUser>() {
                let collides = req
                    .extensions()
                    .get::<AuthenticatedUser>()
                    .is_some_and(|user| {
                        !matches!(
                            user.auth_method,
                            AuthMethod::DefaultUser | AuthMethod::ApiToken
                        ) && names_reserved_identity(
                            user.username.as_str(),
                            &kms_server.params.default_username,
                        )
                    });
                if collides {
                    warn!("External identity collides with the KMS default_username");
                    return Ok(req
                        .into_response(
                            HttpResponse::Unauthorized()
                                .body("external identity collides with the KMS default_username"),
                        )
                        .map_into_boxed_body());
                }
                debug!("Request already authenticated, skipping Ensure Auth middleware");
                return next
                    .call(req)
                    .await
                    .map(ServiceResponse::map_into_boxed_body);
            }

            // Authentication is configured but none was provided — reject.
            if auth_is_configured {
                error!("Authentication method configured, but no authentication provided");
                return Ok(req
                    .into_response(HttpResponse::Unauthorized().body("No authentication provided."))
                    .map_into_boxed_body());
            }

            // No authentication configured — inject the default username.
            req.extensions_mut().insert(AuthenticatedUser {
                username: UserId::from(kms_server.params.default_username.as_str()),
                auth_method: AuthMethod::DefaultUser,
            });
            next.call(req)
                .await
                .map(ServiceResponse::map_into_boxed_body)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{
        App, HttpMessage, HttpResponse,
        body::{BoxBody, MessageBody},
        dev::{ServiceRequest, ServiceResponse},
        http::StatusCode,
        middleware::{Next, from_fn},
        test::{TestRequest, call_service, init_service, read_body},
        web,
    };

    use super::ensure_auth_middleware;
    use crate::{
        config::ClapConfig,
        core::KMS,
        middlewares::{AuthMethod, AuthenticatedUser, UserId},
        tests::test_utils::{https_clap_config, test_kms_with_config},
    };

    const COLLISION: &str = "external identity collides with the KMS default_username";

    /// Stands in for an earlier authentication middleware: injects the `AuthenticatedUser`
    /// registered as app data.
    async fn inject_user<B: MessageBody + 'static>(
        req: ServiceRequest,
        next: Next<B>,
    ) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
        let user = req
            .app_data::<web::Data<AuthenticatedUser>>()
            .map(|user| user.get_ref().clone());
        if let Some(user) = user {
            req.extensions_mut().insert(user);
        }
        next.call(req)
            .await
            .map(ServiceResponse::map_into_boxed_body)
    }

    /// A test KMS whose `default_username` is `admin`.
    async fn admin_kms() -> Arc<KMS> {
        test_kms_with_config(ClapConfig {
            default_username: "admin".to_owned(),
            ..https_clap_config()
        })
        .await
        .unwrap()
    }

    /// Status and body of a request authenticated as `username` by `auth_method`, behind
    /// the `ensure_auth_middleware` of `kms`.
    async fn call_as(
        kms: &Arc<KMS>,
        username: &str,
        auth_method: AuthMethod,
    ) -> (StatusCode, String) {
        let kms = kms.clone();
        let app = init_service(
            App::new()
                .app_data(web::Data::new(AuthenticatedUser {
                    username: UserId::from(username),
                    auth_method,
                }))
                // `wrap` order: the last one runs first, so the user is injected before
                // `ensure_auth_middleware` sees the request.
                .wrap(ensure_auth_middleware(kms, true))
                .wrap(from_fn(inject_user))
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;
        let resp = call_service(&app, TestRequest::get().uri("/").to_request()).await;
        let status = resp.status();
        let body = String::from_utf8(read_body(resp).await.to_vec()).unwrap();
        (status, body)
    }

    /// F-022 (#1486): an externally authenticated identity equal to `default_username`
    /// (in the case- and trailing-space-insensitive sense of the database collations) must
    /// not inherit the default user's objects and exemptions.
    #[actix_web::test]
    async fn external_identity_equal_to_default_username_is_rejected() {
        let kms = admin_kms().await;
        for auth_method in [
            AuthMethod::Mtls,
            AuthMethod::OidcJwt,
            AuthMethod::JwtSvid,
            AuthMethod::AuthVerifierJwt,
            AuthMethod::AuthVerifierSession,
            AuthMethod::Session,
            AuthMethod::SpireToken,
        ] {
            for username in ["admin", "Admin", "admin "] {
                let (status, body) = call_as(&kms, username, auth_method).await;
                assert_eq!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "{auth_method:?} {username:?}: {body}"
                );
                assert!(
                    body.contains(COLLISION),
                    "{auth_method:?} {username:?}: {body}"
                );
            }
        }
    }

    /// The API token and the no-auth fallback legitimately map to `default_username`.
    #[actix_web::test]
    async fn internal_default_username_paths_are_accepted() {
        let kms = admin_kms().await;
        for auth_method in [AuthMethod::ApiToken, AuthMethod::DefaultUser] {
            let (status, body) = call_as(&kms, "admin", auth_method).await;
            assert_eq!(status, StatusCode::OK, "{auth_method:?}: {body}");
        }
    }

    #[actix_web::test]
    async fn external_identity_distinct_from_default_username_is_accepted() {
        let (status, body) = call_as(&admin_kms().await, "alice", AuthMethod::OidcJwt).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}
