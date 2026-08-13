//! Audit middleware — intercepts every KMIP request and enqueues an
//! `AuditEventDraft` to the background writer task after the inner service
//! has produced its response.
//!
//! Design decisions
//! ================
//! * When `store` is `None` (audit disabled) the middleware is a transparent
//!   pass-through: no overhead beyond a single `Option` check.
//! * The middleware is registered **just before** `.wrap(cors)` so it runs
//!   *inside* CORS but *outside* all authentication middlewares.  This means:
//!   - 401 responses from `EnsureAuth`, `JwtAuth`, `TlsAuth` are audited.
//!   - CORS `OPTIONS` preflight requests are **not** audited (they bypass the
//!     audit wrapper because CORS handles them first).
//! * Operation name extraction: the path `/kmip/2_1` → "KMIP", enterprise
//!   paths `/google_cse/…` → `"GoogleCSE"`, etc.  For KMIP requests the
//!   route handler injects a `KmipOperationName` extension with the exact
//!   operation (e.g. `"Encrypt"`, `"Create"`), which overrides the coarse
//!   path-derived name.
//! * User identity: read from `AuthenticatedUser` in request extensions.  If
//!   absent (401 path) we record `"unauthenticated"`.
//! * Duration: measured as wall-clock elapsed from the moment the inner
//!   service `Future` is polled to completion.

mod client_ip;
mod extensions;

pub(crate) use extensions::{
    BatchItemAuditContext, KmipAlgorithm, KmipBatchOperations, KmipObjectUid, KmipOperationName,
};

use std::{
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Instant,
};

use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode,
};
use cosmian_kms_access::audit::{
    AuditEventDraft, AuditResult, OperationAuditContext, RequestAuditContext, audit_now,
};
use futures::{
    Future,
    future::{Ready, ok},
};
use ipnet::IpNet;
use uuid::Uuid;

use self::client_ip::{extract_client_ip, extract_operation};
use crate::{core::audit::AuditStore, middlewares::AuthenticatedUser};

const UNAUTHENTICATED: &str = "unauthenticated";

/// Audit durations are stored in a `PostgreSQL` `BIGINT`, so a value that does not fit in `i64`
/// would not survive a write/read round-trip and would break hash re-verification from the
/// database. The clamp is unreachable in practice (`i64::MAX` ms ≈ 292 million years).
const MAX_AUDIT_DURATION_MS: u64 = i64::MAX.unsigned_abs();

#[derive(Clone)]
pub(crate) struct AuditMiddleware {
    store: Option<AuditStore>,
    /// Only used when parsing `X-Forwarded-For`. Empty means always use peer address.
    trusted_proxies: Vec<IpNet>,
}

impl AuditMiddleware {
    /// Creates a new `AuditMiddleware`.
    ///
    /// When `store` is `None` the middleware is a no-op pass-through.
    /// `trusted_proxies` is the list of CIDR ranges whose `X-Forwarded-For` headers
    /// are trusted; an empty list disables XFF processing entirely.
    #[must_use]
    pub(crate) const fn new(store: Option<AuditStore>, trusted_proxies: Vec<IpNet>) -> Self {
        Self {
            store,
            trusted_proxies,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuditMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = AuditService<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuditService {
            service: Rc::new(service),
            store: self.store.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
        })
    }
}

pub(crate) struct AuditService<S> {
    service: Rc<S>,
    store: Option<AuditStore>,
    trusted_proxies: Vec<IpNet>,
}

impl<S, B> Service<ServiceRequest> for AuditService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let store = match &self.store {
            None => {
                let svc = self.service.clone();
                return Box::pin(async move {
                    let res = svc.call(req).await?;
                    Ok(res.map_into_left_body())
                });
            }
            Some(s) => s.clone(),
        };

        let operation = extract_operation(req.path());
        let client_ip = extract_client_ip(&req, &self.trusted_proxies);

        let start = Instant::now();
        let timestamp = audit_now();
        let svc = self.service.clone();

        Box::pin(async move {
            let res = svc.call(req).await?;

            let duration_ms = u64::try_from(start.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .min(MAX_AUDIT_DURATION_MS);
            let status = res.status();
            let request_id = Uuid::new_v4();

            // AuditMiddleware runs outside the auth middlewares, so the user is only
            // available in the request extensions after `svc.call` returns.
            let final_user = res
                .request()
                .extensions()
                .get::<AuthenticatedUser>()
                .map_or_else(|| UNAUTHENTICATED.to_owned(), |u| u.username.clone());

            let req_ctx = RequestAuditContext {
                timestamp,
                user: final_user,
                client_ip,
                duration_ms,
                request_id: Some(request_id),
            };

            // Batch path: fan out one draft per BatchItem
            let batch_drafts: Option<Vec<AuditEventDraft>> = res
                .request()
                .extensions()
                .get::<KmipBatchOperations>()
                .map(|batch_ops| {
                    batch_ops
                        .0
                        .iter()
                        .map(|ctx| {
                            let item_result = ctx
                                .result
                                .clone()
                                .unwrap_or_else(|| status_to_result(status));
                            let op_ctx = OperationAuditContext {
                                operation: ctx.operation.clone(),
                                object_uid: ctx.object_uid.clone(),
                                algorithm: ctx.algorithm.clone(),
                            };
                            AuditEventDraft::build(&req_ctx, op_ctx, item_result)
                        })
                        .collect()
                });

            if let Some(drafts) = batch_drafts {
                store.enqueue(drafts);
                return Ok(res.map_into_left_body());
            }

            // Single-op path
            let final_operation = res
                .request()
                .extensions()
                .get::<KmipOperationName>()
                .map_or(operation, |k| k.0.clone());

            let object_uid = res
                .request()
                .extensions()
                .get::<KmipObjectUid>()
                .map(|k| k.0.clone());

            let algorithm = res
                .request()
                .extensions()
                .get::<KmipAlgorithm>()
                .map(|k| k.0.clone());

            let op_ctx = OperationAuditContext {
                operation: final_operation,
                object_uid,
                algorithm,
            };
            let draft = AuditEventDraft::build(&req_ctx, op_ctx, status_to_result(status));

            store.enqueue(std::iter::once(draft));

            Ok(res.map_into_left_body())
        })
    }
}

/// Maps an HTTP response status to an [`AuditResult`]: 2xx/3xx is `Success`, anything else is a
/// `Failure` carrying the status line (e.g. `"401 Unauthorized"`).
fn status_to_result(status: StatusCode) -> AuditResult {
    if status.is_success() || status.is_redirection() {
        AuditResult::Success
    } else {
        AuditResult::Failure(format!(
            "{} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use cosmian_kms_access::audit::AuditResult;

    use super::*;

    #[test]
    fn status_to_result_success() {
        assert!(matches!(
            status_to_result(StatusCode::OK),
            AuditResult::Success
        ));
        assert!(matches!(
            status_to_result(StatusCode::FOUND),
            AuditResult::Success
        ));
    }

    #[test]
    fn status_to_result_failure() {
        match status_to_result(StatusCode::UNAUTHORIZED) {
            AuditResult::Failure(msg) => assert_eq!(msg, "401 Unauthorized"),
            AuditResult::Success => panic!("expected Failure"),
        }
    }
}
