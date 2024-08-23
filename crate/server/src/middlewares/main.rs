use std::{
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

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
use tracing::{debug, error, trace, warn};

use super::{manage_jwt_request, manage_token_request, PeerCommonName};
use crate::middlewares::{jwt::JwtConfig, manage_jwt, manage_token};

#[derive(Clone)]
pub(crate) struct AuthTransformer {
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    api_token: Option<Arc<String>>,
}

impl AuthTransformer {
    #[must_use]
    pub(crate) const fn new(
        jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
        api_token: Option<Arc<String>>,
    ) -> Self {
        Self {
            jwt_configurations,
            api_token,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthTransformer
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = AuthMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        debug!("JWT/Token Authentication enabled");
        ok(AuthMiddleware {
            service: Rc::new(service),
            jwt_configurations: self.jwt_configurations.clone(),
            api_token: self.api_token.clone(),
        })
    }
}

pub(crate) struct AuthMiddleware<S> {
    service: Rc<S>,
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    api_token: Option<Arc<String>>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
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

        if req.extensions().contains::<PeerCommonName>() {
            debug!(
                "Request extension PeerCommonName found! Certificate client authentication has \
                 already been done in success, continue..."
            );
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        if let (Some(configurations), Some(api_token)) =
            (self.jwt_configurations.clone(), self.api_token.clone())
        {
            return Box::pin(async move {
                manage_multiple_authentications_request(service, configurations, api_token, req)
                    .await
            });
        }

        if let Some(configurations) = self.jwt_configurations.clone() {
            return Box::pin(async move { manage_jwt_request(service, configurations, req).await });
        }

        if let Some(api_token) = self.api_token.clone() {
            return Box::pin(async move { manage_token_request(service, api_token, req).await });
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

async fn manage_multiple_authentications_request<S, B>(
    service: Rc<S>,
    configs: Arc<Vec<JwtConfig>>,
    api_token: Arc<String>,
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
            warn!("Retry with authentication Token since JWT authentication failed ({e:?})");
            match manage_token(&api_token, &req) {
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
