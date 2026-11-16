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
use cosmian_logger::{debug, error};

use crate::{
    core::KMS,
    middlewares::{AuthMethod, AuthenticatedUser, UserId},
};

/// Creates the authentication fallback middleware.
///
/// Ensures that every request reaching this middleware carries an [`AuthenticatedUser`]:
/// - Passes through if a user was already injected by an earlier middleware.
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
                roles: Vec::new(),
                domain: None,
                auth_method: AuthMethod::DefaultUser,
            });
            next.call(req)
                .await
                .map(ServiceResponse::map_into_boxed_body)
        }
    })
}
