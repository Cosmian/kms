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

/// KMIP-specific operation name injected by the KMIP route handlers
/// so the audit middleware records the exact operation ("Encrypt", "Create", …)
/// instead of the coarse path-derived grouping ("KMIP").
#[derive(Debug, Clone)]
pub(crate) struct KmipOperationName(pub String);

/// KMIP object UID injected by the KMIP route handler for audit purposes.
/// For Create/CreateKeyPair this is the server-generated UID from the response TTLV.
/// For object-bearing ops (Encrypt, Decrypt, Get, Destroy, …) it is the
/// `UniqueIdentifier` from the request TTLV.
#[derive(Debug, Clone)]
pub(crate) struct KmipObjectUid(pub String);

/// KMIP cryptographic algorithm (e.g. `"AES"`, `"RSA"`) injected by the KMIP
/// route handler for audit purposes.
#[derive(Debug, Clone)]
pub(crate) struct KmipAlgorithm(pub String);

/// Per-BatchItem audit context extracted from a `RequestMessage` TTLV.
/// Injected by the KMIP route handler for batch requests.
#[derive(Debug, Clone)]
pub(crate) struct BatchItemAuditContext {
    pub operation: String,
    pub object_uid: Option<String>,
    pub algorithm: Option<String>,
    /// Per-item result backfilled from the `ResponseMessage` after dispatch.
    pub result: Option<cosmian_kms_access::audit::AuditResult>,
}

/// Container for per-`BatchItem` audit contexts extracted from a `RequestMessage`.
/// Injected into request extensions by `inject_audit_request`; consumed by the
/// audit middleware to fan out one `AuditEventDraft` per item.
#[derive(Debug, Clone)]
pub(crate) struct KmipBatchOperations(pub Vec<BatchItemAuditContext>);

use std::{
    net::IpAddr,
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
use cosmian_kms_access::audit::{AuditEventDraft, AuditResult};
use cosmian_logger::error;
use futures::{
    Future,
    future::{Ready, ok},
};
use ipnet::IpNet;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::AuditFailureMode,
    core::audit::{AuditFileStore, make_failure_draft, make_success_draft},
    middlewares::AuthenticatedUser,
};

const UNAUTHENTICATED: &str = "unauthenticated";

#[derive(Clone)]
pub(crate) struct AuditMiddleware {
    store: Option<AuditFileStore>,
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
        store: Option<AuditFileStore>,
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
    store: Option<AuditFileStore>,
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
        let timestamp = OffsetDateTime::now_utc();
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
                .map_or_else(|| UNAUTHENTICATED.to_owned(), |u| u.username.clone());

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
                            AuditEventDraft {
                                timestamp,
                                operation: ctx.operation.clone(),
                                user: final_user.clone(),
                                object_uid: ctx.object_uid.clone(),
                                algorithm: ctx.algorithm.clone(),
                                client_ip: client_ip.clone(),
                                result: item_result,
                                duration_ms,
                                request_id: Some(request_id),
                            }
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

            let mut draft: AuditEventDraft = if status.is_success() || status.is_redirection() {
                make_success_draft(
                    timestamp,
                    final_operation,
                    final_user,
                    object_uid,
                    algorithm,
                    client_ip,
                    duration_ms,
                )
            } else {
                let reason = format!(
                    "{} {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Unknown")
                );
                make_failure_draft(
                    timestamp,
                    final_operation,
                    final_user,
                    object_uid,
                    algorithm,
                    client_ip,
                    duration_ms,
                    reason,
                )
            };
            draft.request_id = Some(request_id);

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

/// Derives an operation name from the HTTP path by taking the first path segment.
///
/// For KMIP requests the route handler injects a `KmipOperationName` extension with
/// the exact operation name — this function only provides the fallback used when no
/// extension is present (non-KMIP paths, or failures before dispatch).
fn extract_operation(path: &str) -> String {
    let segment = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if segment.is_empty() {
        "unknown".to_owned()
    } else {
        segment.to_owned()
    }
}

/// Extracts the client IP address.
///
/// The `X-Forwarded-For` header is only trusted when the direct TCP peer address
/// falls within one of the `trusted_proxies` CIDR ranges.  If the peer is not a
/// trusted proxy, or if `trusted_proxies` is empty, the peer address is used
/// directly — preventing clients from spoofing their apparent IP.
fn extract_client_ip(req: &ServiceRequest, trusted_proxies: &[IpNet]) -> Option<String> {
    let peer_ip = req.peer_addr().map(|a| a.ip());

    let peer_is_trusted = peer_ip
        .as_ref()
        .is_some_and(|ip| trusted_proxies.iter().any(|cidr| cidr.contains(ip)));

    if peer_is_trusted {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(val) = xff.to_str() {
                if let Some(ip) = val.split(',').next() {
                    // Only trust a syntactically valid IP; otherwise fall back to the
                    // peer address so garbage headers never reach the audit log.
                    if let Ok(parsed) = ip.trim().parse::<IpAddr>() {
                        return Some(parsed.to_string());
                    }
                }
            }
        }
    }

    peer_ip.map(|ip| ip.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn operation_extraction_from_paths() {
        assert_eq!(extract_operation("/kmip/2_1"), "kmip");
        assert_eq!(extract_operation("/google_cse/digest"), "google_cse");
        assert_eq!(extract_operation("/ms_dke/version"), "ms_dke");
        assert_eq!(extract_operation("/azure_ekm/keys"), "azure_ekm");
        assert_eq!(extract_operation("/aws_xks/healthcheck"), "aws_xks");
        assert_eq!(extract_operation("/health"), "health");
        assert_eq!(extract_operation("/v1/crypto/encrypt"), "v1");
        assert_eq!(extract_operation("/"), "unknown");
        assert_eq!(extract_operation(""), "unknown");
    }

    #[test]
    fn make_success_draft_all_attributes() {
        use cosmian_kms_access::audit::AuditResult;
        use time::OffsetDateTime;

        use crate::core::audit::make_success_draft;

        let ts = OffsetDateTime::now_utc();

        let draft = make_success_draft(
            ts,
            "Encrypt",
            "alice",
            Some("key-42".to_owned()),
            Some("AES-256".to_owned()),
            Some("192.168.1.1".to_owned()),
            42,
        );
        assert_eq!(draft.timestamp, ts);
        assert_eq!(draft.operation, "Encrypt");
        assert_eq!(draft.user, "alice");
        assert_eq!(draft.object_uid.as_deref(), Some("key-42"));
        assert_eq!(draft.algorithm.as_deref(), Some("AES-256"));
        assert_eq!(draft.client_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(draft.duration_ms, 42);
        assert!(matches!(draft.result, AuditResult::Success));

        let draft = make_success_draft(ts, "Get", "bob", None, None, None, 7);
        assert_eq!(draft.operation, "Get");
        assert_eq!(draft.user, "bob");
        assert!(draft.object_uid.is_none());
        assert!(draft.algorithm.is_none());
        assert!(draft.client_ip.is_none());
        assert_eq!(draft.duration_ms, 7);
        assert!(matches!(draft.result, AuditResult::Success));
    }

    #[test]
    fn make_failure_draft_all_attributes() {
        use cosmian_kms_access::audit::AuditResult;
        use time::OffsetDateTime;

        use crate::core::audit::make_failure_draft;

        let ts = OffsetDateTime::now_utc();

        let draft = make_failure_draft(
            ts,
            "Decrypt",
            "charlie",
            Some("obj-99".to_owned()),
            Some("RSA-3072".to_owned()),
            Some("10.0.0.5".to_owned()),
            123,
            "403 Forbidden",
        );
        assert_eq!(draft.timestamp, ts);
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

        let draft = make_failure_draft(
            ts,
            "Create",
            "dave",
            None,
            None,
            None,
            15,
            "401 Unauthorized",
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

    // ── extract_client_ip tests ──────────────────────────────────────────────

    /// Helper: build a minimal `ServiceRequest` with a given peer address and
    /// optional `X-Forwarded-For` header.  Uses `actix_web::test::TestRequest`.
    fn make_request(peer: &str, xff: Option<&str>) -> actix_web::test::TestRequest {
        let mut req = actix_web::test::TestRequest::default().peer_addr(peer.parse().unwrap());
        if let Some(v) = xff {
            req = req.insert_header(("x-forwarded-for", v));
        }
        req
    }

    #[test]
    fn xff_ignored_when_no_trusted_proxies() {
        let req = make_request("1.2.3.4:9000", Some("10.0.0.1")).to_srv_request();
        let ip = extract_client_ip(&req, &[]);
        assert_eq!(ip.as_deref(), Some("1.2.3.4"), "peer IP used, XFF ignored");
    }

    #[test]
    fn xff_ignored_when_peer_not_in_trusted_cidr() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("1.2.3.4:9000", Some("192.168.1.1")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("1.2.3.4"),
            "peer is not in CIDR, XFF ignored"
        );
    }

    #[test]
    fn xff_used_when_peer_in_trusted_cidr() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.1:9000", Some("203.0.113.5")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("203.0.113.5"),
            "peer in CIDR, XFF first IP used"
        );
    }

    #[test]
    fn xff_first_ip_taken_from_comma_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.2:9000", Some("203.0.113.5, 10.0.0.1")).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(ip.as_deref(), Some("203.0.113.5"), "first XFF entry used");
    }

    #[test]
    fn xff_absent_with_trusted_proxy_falls_back_to_peer() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let req = make_request("10.0.0.1:9000", None).to_srv_request();
        let ip = extract_client_ip(&req, &cidrs);
        assert_eq!(
            ip.as_deref(),
            Some("10.0.0.1"),
            "no XFF header, peer IP used"
        );
    }
}
