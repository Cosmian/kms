//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.

use std::sync::Arc;

use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::{Next, from_fn},
};
use cosmian_logger::debug;

use crate::{
    core::KMS,
    middlewares::{AuthenticatedUser, api_token::api_token_auth::handle_api_token},
};

/// Creates the API token authentication middleware.
///
/// Validates API tokens on each request and injects [`AuthenticatedUser`] into the request
/// extensions on success. Skips authentication if a user was already injected by an earlier
/// middleware in the chain.
pub(crate) fn api_token_middleware<S, B>(
    kms_server: Arc<KMS>,
) -> impl Transform<S, ServiceRequest, Response = ServiceResponse<B>, Error = Error, InitError = ()>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    from_fn(move |req: ServiceRequest, next: Next<B>| {
        let kms_server = kms_server.clone();
        async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "API Token Middleware: An authenticated user was found; there is no need to \
                     authenticate twice..."
                );
            } else {
                match handle_api_token(&kms_server, &req).await {
                    Ok(()) => {
                        req.extensions_mut().insert(AuthenticatedUser {
                            username: kms_server.params.default_username.clone(),
                        });
                    }
                    Err(e) => {
                        debug!("API token authentication failed: {e:?}");
                    }
                }
            }
            next.call(req).await
        }
    })
}
