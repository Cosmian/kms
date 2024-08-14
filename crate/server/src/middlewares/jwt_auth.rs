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
    http::header,
    Error, FromRequest, HttpMessage, HttpResponse,
};
use futures::{
    future::{ok, Ready},
    Future,
};
use tracing::{debug, error, trace};

use super::UserClaim;
use crate::{error::KmsError, middlewares::jwt::JwtConfig, result::KResult};

#[derive(Clone)]
pub(crate) struct JwtAuth {
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    authentication_token: Option<Arc<String>>,
}

impl JwtAuth {
    #[must_use]
    pub(crate) const fn new(
        jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
        authentication_token: Option<Arc<String>>,
    ) -> Self {
        Self {
            jwt_configurations,
            authentication_token,
        }
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
        debug!("JWT/Token Authentication enabled");
        ok(JwtAuthMiddleware {
            service: Rc::new(service),
            jwt_configurations: self.jwt_configurations.clone(),
            authentication_token: self.authentication_token.clone(),
        })
    }
}

pub(crate) struct JwtAuthMiddleware<S> {
    service: Rc<S>,
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    authentication_token: Option<Arc<String>>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
        let service = self.service.clone();

        if let (Some(configurations), Some(authentication_token)) = (
            self.jwt_configurations.clone(),
            self.authentication_token.clone(),
        ) {
            return Box::pin(async move {
                manage_request(service, configurations, authentication_token, req).await
            });
        }

        if let Some(configurations) = self.jwt_configurations.clone() {
            return Box::pin(async move { manage_jwt_request(service, configurations, req).await });
        }

        if let Some(authentication_token) = self.authentication_token.clone() {
            return Box::pin(async move {
                manage_token_request(service, authentication_token, req).await
            });
        }

        Box::pin(async move {
            error!(
                "{:?} {} 401 unauthorized: JWT/Token authentications not properly configured on \
                 KMS server",
                req.method(),
                req.path(),
            );
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        })
    }
}

async fn manage_request<S, B>(
    service: Rc<S>,
    configs: Arc<Vec<JwtConfig>>,
    authentication_token: Arc<String>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("JWT then Token Authentication...");
    match manage_jwt(configs, &req).await {
        Ok(auth_claim) => {
            req.extensions_mut().insert(auth_claim);
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        }
        Err(e) => {
            error!("Retry with authentication Token since JWT authentication failed ({e:?})");
            match manage_token(&authentication_token, &req) {
                Ok(true) => {
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Ok(false) => {
                    error!(
                        "{:?} {} 401 unauthorized: Client and server authentication tokens \
                         mismatch",
                        req.method(),
                        req.path(),
                    );
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish())
                        .map_into_right_body())
                }
                Err(e) => {
                    error!("Token authentication failed: {:?}", e);
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish())
                        .map_into_right_body())
                }
            }
        }
    }
}

async fn manage_jwt_request<S, B>(
    service: Rc<S>,
    configs: Arc<Vec<JwtConfig>>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("JWT Authentication...");
    match manage_jwt(configs, &req).await {
        Ok(auth_claim) => {
            req.extensions_mut().insert(auth_claim);
            Ok(service.call(req).await?.map_into_left_body())
        }
        Err(e) => {
            error!("{:?} {} 401 unauthorized: {e:?}", req.method(), req.path(),);
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
    }
}

async fn manage_token_request<S, B>(
    service: Rc<S>,
    authentication_token: Arc<String>,
    req: ServiceRequest,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    trace!("Token Authentication...");
    match manage_token(&authentication_token, &req) {
        Ok(auth_claim) => {
            req.extensions_mut().insert(auth_claim);
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        }
        Err(e) => {
            error!("{:?} {} 401 unauthorized: {e:?}", req.method(), req.path(),);
            Ok(req
                .into_response(HttpResponse::Unauthorized().finish())
                .map_into_right_body())
        }
    }
}

fn extract_user_claim(configs: &[JwtConfig], identity: &str) -> Result<UserClaim, Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();
    for idp_config in configs {
        match idp_config.decode_bearer_header(identity) {
            Ok(user_claim) => return Ok(user_claim),
            Err(error) => {
                jwt_log_errors.push(error);
            }
        }
    }
    Err(jwt_log_errors)
}

async fn manage_jwt(configs: Arc<Vec<JwtConfig>>, req: &ServiceRequest) -> KResult<JwtAuthClaim> {
    trace!("JWT Authentication...");

    let identity = Identity::extract(req.request())
        .into_inner()
        .map_or_else(
            |_| {
                req.headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
            },
            |identity| identity.id().ok(),
        )
        .unwrap_or_default();

    trace!("Checking JWT identity: {identity}");

    let mut private_claim = extract_user_claim(&configs, &identity);
    // If no configuration could get the claim, try refreshing them and extract user claim again
    if private_claim.is_err() {
        configs[0].jwks.refresh().await?;
        private_claim = extract_user_claim(&configs, &identity);
    }

    match private_claim.map(|user_claim| user_claim.email) {
        Ok(Some(email)) => {
            debug!("JWT Access granted to {email}!");
            Ok(JwtAuthClaim::new(email))
        }
        Ok(None) => {
            error!(
                "{:?} {} 401 unauthorized, no email in JWT",
                req.method(),
                req.path()
            );
            Err(KmsError::InvalidRequest("No email in JWT".to_owned()))
        }
        Err(jwt_log_errors) => {
            for error in &jwt_log_errors {
                tracing::error!("{error:?}");
            }
            error!(
                "{:?} {} 401 unauthorized: bad JWT",
                req.method(),
                req.path(),
            );
            Err(KmsError::InvalidRequest("bad JWT".to_owned()))
        }
    }
}

#[derive(Debug)]
pub(crate) struct JwtAuthClaim {
    pub email: String,
}

impl JwtAuthClaim {
    #[must_use]
    pub(crate) const fn new(email: String) -> Self {
        Self { email }
    }
}

fn manage_token(authentication_token: &Arc<String>, req: &ServiceRequest) -> KResult<bool> {
    trace!("Token authentication...");
    let client_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or_else(|| KmsError::InvalidRequest("Missing Authorization header".to_string()))?
        .to_str()
        .map_err(|e| {
            KmsError::InvalidRequest(format!("Error converting header value to string: {e:?}"))
        })?
        .split("Bearer")
        .collect::<Vec<&str>>();

    if client_token.len() != 2 {
        return Err(KmsError::InvalidRequest(format!(
            "Invalid Authorization header format: expected: \"Bearer <my_token>\", got \
             {client_token:?}"
        )));
    }

    if client_token[1].trim_start() == authentication_token.as_str() {
        debug!("Token authentication successful");
        Ok(true)
    } else {
        error!(
            "{:?} {} 401 unauthorized: Client and server authentication tokens mismatch",
            req.method(),
            req.path(),
        );
        Ok(false)
    }
}
