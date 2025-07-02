use std::{
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_web::{
    Error,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use futures::{
    Future,
    future::{Ready, ok},
};
use tracing::info;

/// Middleware to log every incoming request (even for 404 or failed auth)
#[derive(Clone)]
pub(crate) struct LogAllRequests;

impl<S, B> Transform<S, ServiceRequest> for LogAllRequests
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = LogAllRequestsMiddleware<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(LogAllRequestsMiddleware {
            service: Rc::new(service),
        })
    }
}

pub(crate) struct LogAllRequestsMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for LogAllRequestsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_owned();
        let peer_addr = req
            .connection_info()
            .realip_remote_addr()
            .map(std::borrow::ToOwned::to_owned);

        let service = self.service.clone();

        Box::pin(async move {
            let res = service.call(req).await;

            match res {
                Ok(ok_res) => {
                    info!(
                        "[{}] {} from {:?} => {}",
                        method,
                        path,
                        peer_addr,
                        ok_res.status()
                    );
                    Ok(ok_res.map_into_left_body())
                }
                Err(err) => {
                    info!(
                        "[{}] {} from {:?} => internal error: {}",
                        method, path, peer_addr, err
                    );
                    Err(err)
                }
            }
        })
    }
}
