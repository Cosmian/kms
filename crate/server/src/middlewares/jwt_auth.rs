use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use actix_identity::Identity;
use actix_service::{Service, Transform};
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
    Error, FromRequest, HttpMessage, HttpResponse,
};
use futures::{
    future::{ok, Ready},
    Future,
};
use tracing::{debug, error, trace};

use crate::middlewares::jwt::JwtConfig;

#[derive(Clone)]
pub struct JwtAuth {
    jwt_config: Option<Arc<JwtConfig>>,
}

impl JwtAuth {
    #[must_use]
    pub fn new(jwt_config: Option<Arc<JwtConfig>>) -> Self {
        Self { jwt_config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = JwtAuthMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        debug!("JWT Authentication enabled");
        ok(JwtAuthMiddleware {
            service,
            jwt_config: self.jwt_config.clone(),
        })
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
    jwt_config: Option<Arc<JwtConfig>>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // get the JWT config
        let Some(jwt_config) = &self.jwt_config else {
            return Box::pin(async move {
                error!(
                    "{:?} {} 401 unauthorized: JWT not properly configured on KMS server",
                    req.method(),
                    req.path(),
                );
                Ok(req
                    .into_response(HttpResponse::Unauthorized().finish())
                    .map_into_right_body())
            })
        };

        trace!("JWT Authentication...");

        // get the identity from the authorization header
        let identity = Identity::extract(req.request())
            .into_inner()
            .map_or_else(
                |_| {
                    req.headers()
                        .get("Authorization")
                        .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
                },
                |identity| identity.id().ok(),
            )
            .unwrap_or_default();
        trace!("Checking JWT identity: {identity:?}");

        // decode the JWT
        let private_claim = {
            let private_claim = jwt_config
                .decode_bearer_header(&identity)
                .map(|claim| claim.email);

            // if an error occured, try to fetch JWKS again
            if private_claim.is_err() {
                jwt_config.jwks.refresh();
            }

            jwt_config
                .decode_bearer_header(&identity)
                .map(|claim| claim.email)
        };

        match private_claim {
            Err(e) => Box::pin(async move {
                error!(
                    "{:?} {} 401 unauthorized: bad JWT ({})",
                    req.method(),
                    req.path(),
                    e
                );
                Ok(req
                    .into_response(HttpResponse::Unauthorized().finish())
                    .map_into_right_body())
            }),
            Ok(None) => Box::pin(async move {
                error!(
                    "{:?} {} 401 unauthorized, no email in JWT",
                    req.method(),
                    req.path()
                );
                Ok(req
                    .into_response(HttpResponse::Unauthorized().finish())
                    .map_into_right_body())
            }),
            Ok(Some(email)) => {
                // forward to the endpoint the email got from this JWT
                debug!("JWT Access granted to {email} !");
                req.extensions_mut().insert(JwtAuthClaim::new(email));

                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                })
            }
        }
    }
}

#[derive(Debug)]
pub struct JwtAuthClaim {
    pub email: String,
}

impl JwtAuthClaim {
    #[must_use]
    pub fn new(email: String) -> Self {
        Self { email }
    }
}
