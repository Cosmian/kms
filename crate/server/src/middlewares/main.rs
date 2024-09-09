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
    Error, HttpMessage,
};
use futures::{
    future::{ok, Ready},
    Future,
};
use tracing::debug;

use super::{manage_api_token_request, manage_jwt_request, PeerCommonName};
use crate::{core::KMS, middlewares::jwt::JwtConfig};

#[derive(Clone)]
pub(crate) struct AuthTransformer {
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    kms_server: Arc<KMS>,
}

impl AuthTransformer {
    #[must_use]
    pub(crate) const fn new(
        kms_server: Arc<KMS>,
        jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    ) -> Self {
        Self {
            jwt_configurations,
            kms_server,
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
        ok(AuthMiddleware {
            service: Rc::new(service),
            jwt_configurations: self.jwt_configurations.clone(),
            kms_server: self.kms_server.clone(),
        })
    }
}

pub(crate) struct AuthMiddleware<S> {
    service: Rc<S>,
    jwt_configurations: Option<Arc<Vec<JwtConfig>>>,
    kms_server: Arc<KMS>,
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

    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        if req.extensions().contains::<PeerCommonName>() {
            debug!(
                "Request extension PeerCommonName found! Certificate client authentication has \
                 already been done in success, no need to authenticate twice..."
            );
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            });
        }

        if let Some(configurations) = self.jwt_configurations.clone() {
            return Box::pin(async move { manage_jwt_request(service, configurations, req).await });
        }

        let kms_server = self.kms_server.clone();
        Box::pin(async move { manage_api_token_request(service, kms_server, req).await })
    }
}
