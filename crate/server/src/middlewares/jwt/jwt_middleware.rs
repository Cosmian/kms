//! JWT Authentication Middleware
//!
//! This module contains the middleware implementation for JWT-based authentication.
//! It verifies and validates JWT tokens in incoming requests.

use std::sync::Arc;

use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::{Next, from_fn},
};
use cosmian_logger::debug;

use crate::middlewares::{
    AuthenticatedUser,
    jwt::{JwtConfig, jwt_token_auth::handle_jwt},
};

/// Creates the JWT authentication middleware.
///
/// Validates JWT bearer tokens on each request and injects [`AuthenticatedUser`] into the
/// request extensions on success. Skips authentication if a user was already injected by an
/// earlier middleware in the chain.
pub(crate) fn jwt_auth_middleware<S, B>(
    jwt_configurations: Arc<Vec<JwtConfig>>,
) -> impl Transform<S, ServiceRequest, Response = ServiceResponse<B>, Error = Error, InitError = ()>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    from_fn(move |req: ServiceRequest, next: Next<B>| {
        let jwt_configurations = jwt_configurations.clone();
        async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "JWT: An authenticated user was found; there is no need to authenticate \
                     twice..."
                );
            } else {
                match handle_jwt(jwt_configurations, &req).await {
                    Ok(auth_claim) => {
                        req.extensions_mut().insert(auth_claim);
                    }
                    Err(e) => {
                        debug!("JWT authentication failed: {e:?}");
                    }
                }
            }
            next.call(req).await
        }
    })
}
