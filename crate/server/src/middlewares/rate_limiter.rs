//! Peer-IP rate-limiting middleware backed by the `governor` crate (MIT/Apache-2.0).
//!
//! This replaces the GPL-licensed `actix-governor` wrapper with a minimal
//! direct implementation that uses a keyed rate limiter on the peer IP address.

use std::{
    cell::RefCell,
    future::{self, Ready},
    net::IpAddr,
    num::NonZeroU32,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use futures::{
    TryFutureExt,
    future::{Either, MapOk},
};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::keyed::DefaultKeyedStateStore,
};

type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
type ServiceFuture<S, B> = MapOk<
    <S as Service<ServiceRequest>>::Future,
    fn(ServiceResponse<B>) -> ServiceResponse<EitherBody<B>>,
>;

/// Configuration for the rate-limiting middleware.
#[derive(Clone)]
pub(crate) struct RateLimiterConfig {
    limiter: Arc<KeyedLimiter>,
}

impl RateLimiterConfig {
    /// Build a rate limiter that allows `requests_per_second` with a burst of `burst_size`.
    ///
    /// Both parameters must be non-zero; passing zero for either value causes
    /// this constructor to fall back to a minimal-throughput limiter (1 req/s,
    /// burst 1) rather than silently disabling rate limiting.
    pub(crate) fn new(requests_per_second: u64, burst_size: u32) -> Self {
        // Reject zero values: fall back to 1 so the limiter is never bypassed.
        let rps = requests_per_second.max(1);
        let burst = NonZeroU32::new(burst_size).unwrap_or(NonZeroU32::MIN);
        let period = Duration::from_nanos(1_000_000_000_u64 / rps);
        let quota = Quota::with_period(period)
            .unwrap_or_else(|| Quota::per_second(NonZeroU32::MIN))
            .allow_burst(burst);
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

/// Actix-web middleware factory for rate limiting by peer IP.
#[derive(Clone)]
pub(crate) struct RateLimiterMiddleware {
    config: RateLimiterConfig,
}

impl RateLimiterMiddleware {
    pub(crate) fn new(config: &RateLimiterConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiterMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: actix_web::body::MessageBody,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B>>;
    type Transform = RateLimiterService<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(RateLimiterService {
            service: Rc::new(RefCell::new(service)),
            limiter: self.config.limiter.clone(),
        }))
    }
}

pub(crate) struct RateLimiterService<S> {
    service: Rc<RefCell<S>>,
    limiter: Arc<KeyedLimiter>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: actix_web::body::MessageBody,
{
    type Error = Error;
    type Future = Either<ServiceFuture<S, B>, Ready<Result<Self::Response, Self::Error>>>;
    type Response = ServiceResponse<EitherBody<B>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let peer_ip = req
            .peer_addr()
            .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |addr| {
                addr.ip()
            });

        match self.limiter.check_key(&peer_ip) {
            Ok(()) => {
                let fut = self.service.call(req);
                Either::Left(fut.map_ok(ServiceResponse::map_into_left_body))
            }
            Err(negative) => {
                let wait_time = negative
                    .wait_time_from(DefaultClock::default().now())
                    .as_secs()
                    .max(1); // Ensure at least 1s to prevent immediate-retry loops
                let response = HttpResponse::TooManyRequests()
                    .insert_header(("retry-after", wait_time.to_string()))
                    .insert_header(("x-ratelimit-after", wait_time.to_string()))
                    .finish();
                let response = req.into_response(response);
                Either::Right(future::ready(Ok(response.map_into_right_body())))
            }
        }
    }
}
