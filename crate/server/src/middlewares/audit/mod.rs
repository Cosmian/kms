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
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use client_ip::{extract_client_ip, extract_operation};
use cosmian_kms_access::audit::{
    AuditEventDraft, AuditResult, OperationAuditContext, RequestAuditContext, audit_now,
};
use cosmian_logger::error;
use futures::{
    Future,
    future::{Ready, ok},
};
use ipnet::IpNet;
use uuid::Uuid;

use crate::{config::AuditFailureMode, core::audit::AuditStore, middlewares::AuthenticatedUser};

const UNAUTHENTICATED: &str = "unauthenticated";

#[derive(Clone)]
pub(crate) struct AuditMiddleware {
    store: Option<AuditStore>,
    failure_mode: AuditFailureMode,
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
    pub(crate) const fn new(
        store: Option<AuditStore>,
        trusted_proxies: Vec<IpNet>,
        failure_mode: AuditFailureMode,
    ) -> Self {
        Self {
            store,
            failure_mode,
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
            failure_mode: self.failure_mode.clone(),
        })
    }
}

pub(crate) struct AuditService<S> {
    service: Rc<S>,
    store: Option<AuditStore>,
    trusted_proxies: Vec<IpNet>,
    failure_mode: AuditFailureMode,
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
        let failure_mode = self.failure_mode.clone();

        let start = Instant::now();
        let timestamp = audit_now();
        let svc = self.service.clone();

        Box::pin(async move {
            let res = svc.call(req).await?;

            let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let status = res.status();
            let request_id = Uuid::new_v4();

            // AuditMiddleware runs outside the auth middlewares, so the user is only
            // available in the request extensions after `svc.call` returns.
            let final_user = res
                .request()
                .extensions()
                .get::<AuthenticatedUser>()
                .map_or_else(|| UNAUTHENTICATED.to_owned(), |u| u.username.to_string());

            let req_ctx = RequestAuditContext {
                timestamp,
                user: final_user,
                client_ip,
                duration_ms,
                request_id: Some(request_id),
            };

            // Batch path: fan out one draft per BatchItem, all sharing `req_ctx`.
            let batch_drafts: Option<Vec<AuditEventDraft>> = res
                .request()
                .extensions()
                .get::<KmipBatchOperations>()
                .map(|batch_ops| {
                    batch_ops
                        .0
                        .iter()
                        .map(|ctx| {
                            let item_result = ctx.result.clone().unwrap_or_else(|| {
                                if status.is_success() || status.is_redirection() {
                                    AuditResult::Success
                                } else {
                                    AuditResult::Failure(format!(
                                        "{} {}",
                                        status.as_u16(),
                                        status.canonical_reason().unwrap_or("Unknown")
                                    ))
                                }
                            });
                            AuditEventDraft::build(
                                &req_ctx,
                                OperationAuditContext {
                                    operation: ctx.operation.clone(),
                                    object_uid: ctx.object_uid.clone(),
                                    algorithm: ctx.algorithm.clone(),
                                },
                                item_result,
                            )
                        })
                        .collect()
                });

            if let Some(drafts) = batch_drafts {
                let all_queued = store.enqueue(drafts);
                if !all_queued && failure_mode == AuditFailureMode::Reject {
                    error!("audit: event(s) not queued — rejecting response (reject mode)");
                    let req = res.request().clone();
                    return Ok(ServiceResponse::new(
                        req,
                        HttpResponse::ServiceUnavailable().body("Service unavailable"),
                    )
                    .map_into_right_body());
                }
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
            let result = if status.is_success() || status.is_redirection() {
                AuditResult::Success
            } else {
                AuditResult::Failure(format!(
                    "{} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown")
                ))
            };
            let draft = AuditEventDraft::build(&req_ctx, op_ctx, result);

            let all_queued = store.enqueue(std::iter::once(draft));
            if !all_queued && failure_mode == AuditFailureMode::Reject {
                error!("audit: event not queued — rejecting response (reject mode)");
                let req = res.request().clone();
                return Ok(ServiceResponse::new(
                    req,
                    HttpResponse::ServiceUnavailable().body("Service unavailable"),
                )
                .map_into_right_body());
            }

            Ok(res.map_into_left_body())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn build_success_draft_all_attributes() {
        use cosmian_kms_access::audit::{AuditResult, OperationAuditContext, RequestAuditContext};
        use time::OffsetDateTime;

        let req = RequestAuditContext {
            timestamp: OffsetDateTime::now_utc(),
            user: "alice".to_owned(),
            client_ip: Some("192.168.1.1".to_owned()),
            duration_ms: 42,
            request_id: None,
        };
        let draft = AuditEventDraft::build(
            &req,
            OperationAuditContext {
                operation: "Encrypt".to_owned(),
                object_uid: Some("key-42".to_owned()),
                algorithm: Some("AES-256".to_owned()),
            },
            AuditResult::Success,
        );
        assert_eq!(draft.timestamp, req.timestamp);
        assert_eq!(draft.operation, "Encrypt");
        assert_eq!(draft.user, "alice");
        assert_eq!(draft.object_uid.as_deref(), Some("key-42"));
        assert_eq!(draft.algorithm.as_deref(), Some("AES-256"));
        assert_eq!(draft.client_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(draft.duration_ms, 42);
        assert!(matches!(draft.result, AuditResult::Success));

        let draft = AuditEventDraft::build(
            &RequestAuditContext {
                user: "bob".to_owned(),
                client_ip: None,
                ..req
            },
            OperationAuditContext {
                operation: "Get".to_owned(),
                ..Default::default()
            },
            AuditResult::Success,
        );
        assert_eq!(draft.operation, "Get");
        assert_eq!(draft.user, "bob");
        assert!(draft.object_uid.is_none());
        assert!(draft.algorithm.is_none());
        assert!(draft.client_ip.is_none());
        assert!(matches!(draft.result, AuditResult::Success));
    }

    #[test]
    fn build_failure_draft_all_attributes() {
        use cosmian_kms_access::audit::{AuditResult, OperationAuditContext, RequestAuditContext};
        use time::OffsetDateTime;

        let req = RequestAuditContext {
            timestamp: OffsetDateTime::now_utc(),
            user: "charlie".to_owned(),
            client_ip: Some("10.0.0.5".to_owned()),
            duration_ms: 123,
            request_id: None,
        };
        let draft = AuditEventDraft::build(
            &req,
            OperationAuditContext {
                operation: "Decrypt".to_owned(),
                object_uid: Some("obj-99".to_owned()),
                algorithm: Some("RSA-3072".to_owned()),
            },
            AuditResult::Failure("403 Forbidden".to_owned()),
        );
        assert_eq!(draft.timestamp, req.timestamp);
        assert_eq!(draft.operation, "Decrypt");
        assert_eq!(draft.user, "charlie");
        assert_eq!(draft.object_uid.as_deref(), Some("obj-99"));
        assert_eq!(draft.algorithm.as_deref(), Some("RSA-3072"));
        assert_eq!(draft.client_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(draft.duration_ms, 123);
        assert!(matches!(
            &draft.result,
            AuditResult::Failure(reason) if reason == "403 Forbidden"
        ));

        let draft = AuditEventDraft::build(
            &RequestAuditContext {
                user: "dave".to_owned(),
                client_ip: None,
                duration_ms: 15,
                ..req
            },
            OperationAuditContext {
                operation: "Create".to_owned(),
                ..Default::default()
            },
            AuditResult::Failure("401 Unauthorized".to_owned()),
        );
        assert_eq!(draft.operation, "Create");
        assert_eq!(draft.user, "dave");
        assert!(draft.object_uid.is_none());
        assert!(draft.algorithm.is_none());
        assert!(draft.client_ip.is_none());
        assert_eq!(draft.duration_ms, 15);
        assert!(matches!(
            &draft.result,
            AuditResult::Failure(reason) if reason == "401 Unauthorized"
        ));
    }
}
