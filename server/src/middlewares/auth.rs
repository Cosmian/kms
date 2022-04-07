use std::{
    pin::Pin,
    task::{Context, Poll},
};

use actix_identity::RequestIdentity;
use actix_service::{Service, Transform};
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage, HttpResponse,
};
use futures::{
    future::{ok, Ready},
    Future,
};
use tracing::{debug, error};

use crate::auth::decode_jwt_new;

pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = AuthMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddleware { service })
    }
}

pub struct AuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
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
        debug!("Authentication...");

        let identity = RequestIdentity::get_identity(&req)
            .or_else(|| {
                req.headers()
                    .get("Authorization")
                    .and_then(|h| h.to_str().ok().map(|h| h.to_string()))
            })
            .unwrap_or_default();

        debug!("Checking JWT");
        let private_claim = decode_jwt_new(&identity).map(|claim| claim.email);
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
                req.extensions_mut().insert(AuthClaim::new(email));

                debug!("access granted !");

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
pub struct AuthClaim {
    pub email: String,
}

impl AuthClaim {
    fn new(email: String) -> Self {
        AuthClaim { email }
    }
}
