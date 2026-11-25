//! Peer-IP rate-limiting middleware backed by the `governor` crate (MIT/Apache-2.0).
//!
//! This replaces the GPL-licensed `actix-governor` wrapper with a minimal
//! direct implementation that uses a keyed rate limiter on the peer IP address.

use std::{
    cell::RefCell,
    future::{self, Ready},
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use actix_web::{
    Error, HttpRequest, HttpResponse,
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
use ipnet::IpNet;

use super::{forwarded_for, resolve_client_ip};

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

/// Quota of `POST /ui/login_as` per peer IP, per minute (the burst is the same).
const LOGIN_AS_PER_IP_PER_MINUTE: u32 = 10;

/// Quota of `POST /ui/login_as` per username, per minute (the burst is the same).
const LOGIN_AS_PER_USER_PER_MINUTE: u32 = 5;

/// Keys tracked by either limiter above which the idle ones are dropped, bounding the memory
/// an attacker spraying random usernames can claim.
const LOGIN_AS_MAX_TRACKED_KEYS: usize = 10_000;

/// Seconds to wait before `negative`'s quota admits a request again; at least 1.
fn retry_after_secs(negative: &governor::NotUntil<<DefaultClock as Clock>::Instant>) -> u64 {
    negative
        .wait_time_from(DefaultClock::default().now())
        .as_secs()
        .max(1)
}

/// Brute-force throttle of the Auth Verifier password login (`POST /ui/login_as`): the
/// handler relays credentials to the Auth Verifier, so each attempt is limited per client IP
/// and per username (case-insensitive). Always enabled; shared by all workers as `app_data`.
/// The client IP is the peer, or the `X-Forwarded-For` entry set by a trusted proxy.
pub(crate) struct LoginAsLimiter {
    per_ip: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>,
    per_user: RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>,
    trusted_proxies: Vec<IpNet>,
}

impl LoginAsLimiter {
    /// A limiter of 10 attempts per minute per IP and 5 per minute per username, honouring
    /// `X-Forwarded-For` only from `trusted_proxies` (the audit trusted-proxy list).
    pub(crate) fn new(trusted_proxies: Vec<IpNet>) -> Self {
        let quota = |per_minute: u32| {
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::MIN))
        };
        Self {
            per_ip: RateLimiter::keyed(quota(LOGIN_AS_PER_IP_PER_MINUTE)),
            per_user: RateLimiter::keyed(quota(LOGIN_AS_PER_USER_PER_MINUTE)),
            trusted_proxies,
        }
    }

    /// The address `req` is throttled under: the peer, or the client a trusted proxy reports.
    pub(crate) fn client_ip(&self, req: &HttpRequest) -> IpAddr {
        resolve_client_ip(
            req.peer_addr().map(|addr| addr.ip()),
            || forwarded_for(req.headers()),
            &self.trusted_proxies,
        )
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    /// Counts one login attempt of `username` from `ip`.
    ///
    /// # Errors
    ///
    /// The number of seconds to wait (at least 1) when either quota is exhausted.
    pub(crate) fn check(&self, ip: IpAddr, username: &str) -> Result<(), u64> {
        if self.per_ip.len() > LOGIN_AS_MAX_TRACKED_KEYS {
            self.per_ip.retain_recent();
        }
        if self.per_user.len() > LOGIN_AS_MAX_TRACKED_KEYS {
            self.per_user.retain_recent();
        }
        self.per_ip
            .check_key(&ip)
            .map_err(|negative| retry_after_secs(&negative))?;
        self.per_user
            .check_key(&username.to_ascii_lowercase())
            .map_err(|negative| retry_after_secs(&negative))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::LoginAsLimiter;

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn login_as_is_limited_per_username_case_insensitively() {
        let limiter = LoginAsLimiter::new(Vec::new());
        for _ in 0..5 {
            assert_eq!(limiter.check(IP_A, "Alice"), Ok(()));
        }
        assert!(limiter.check(IP_A, "alice").is_err_and(|secs| secs >= 1));
        assert_eq!(
            limiter.check(IP_B, "bob"),
            Ok(()),
            "another user is unaffected"
        );
        assert!(
            limiter.check(IP_B, "ALICE").is_err(),
            "the username quota does not depend on the IP"
        );
    }

    #[test]
    fn login_as_is_limited_per_ip() {
        let limiter = LoginAsLimiter::new(Vec::new());
        for user in 0..10 {
            assert_eq!(limiter.check(IP_A, &format!("user{user}")), Ok(()));
        }
        assert!(limiter.check(IP_A, "user10").is_err());
        assert_eq!(limiter.check(IP_B, "user10"), Ok(()));
    }
}
