use std::{
    pin::Pin,
    rc::Rc,
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
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
}

impl JwtAuth {
    #[must_use]
    pub fn new(jwt_configurations: Option<Arc<Vec<JwtConfig>>>) -> Self {
        Self { jwt_configurations }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
            service: Rc::new(service),
            jwt_configurations: self.jwt_configurations.clone(),
        })
    }
}

pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
{
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        if let Some(configurations) = self.jwt_configurations.clone() {
            Box::pin(async move { manage_jwt_request(service, configurations, req).await })
        } else {
            Box::pin(async move {
                error!(
                    "{:?} {} 401 unauthorized: JWT not properly configured on KMS server",
                    req.method(),
                    req.path(),
                );
                Ok(req
                    .into_response(HttpResponse::Unauthorized().finish())
                    .map_into_right_body())
            })
        }
    }
}

async fn manage_jwt_request<S, B>(
    service: Rc<S>,
    configs: Arc<Vec<JwtConfig>>,
    request: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("JWT Authentication...");

    let identity = Identity::extract(request.request())
        .into_inner()
        .map_or_else(
            |_| {
                request
                    .headers()
                    .get("Authorization")
                    .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
            },
            |identity| identity.id().ok(),
        )
        .unwrap_or_default();

    trace!("Checking JWT identity: {identity:?}");

    let extract_user_claim = || {
        let mut jwt_log_errors = Vec::new();
        for idp_config in configs.iter() {
            match idp_config.decode_bearer_header(&identity) {
                Ok(user_claim) => return Ok(user_claim),
                Err(error) => {
                    jwt_log_errors.push(error);
                }
            }
        }
        Err(jwt_log_errors)
    };

    let mut private_claim = extract_user_claim();
    // If no configuration could get the claim, try refreshing them and extract user claim again
    if private_claim.is_err() {
        configs[0].jwks.refresh().await?;
        private_claim = extract_user_claim();
    }

    match private_claim.map(|user_claim| user_claim.email) {
        Ok(Some(email)) => {
            debug!("JWT Access granted to {email} !");
            request.extensions_mut().insert(JwtAuthClaim::new(email));
            let res = service.call(request).await?;
            Ok(res.map_into_left_body())
        }
        Ok(None) => {
            error!(
                "{:?} {} 401 unauthorized, no email in JWT",
                request.method(),
                request.path()
            );
            Ok(request
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
        Err(jwt_log_errors) => {
            for error in jwt_log_errors.iter() {
                tracing::info!("{error:?}");
            }
            error!(
                "{:?} {} 401 unauthorized: bad JWT",
                request.method(),
                request.path(),
            );
            Ok(request
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
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
