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
};
use cosmian_kms_access::audit::AuditEventDraft;
use futures::{
    Future,
    future::{Ready, ok},
};
use time::OffsetDateTime;

use crate::{
    core::audit::{AuditFileStore, make_failure_draft, make_success_draft},
    middlewares::AuthenticatedUser,
};

const UNAUTHENTICATED: &str = "unauthenticated";

#[derive(Clone)]
pub(crate) struct AuditMiddleware {
    store: Option<AuditFileStore>,
}

impl AuditMiddleware {
    /// Creates a new `AuditMiddleware`.
    ///
    /// When `store` is `None` the middleware is a no-op pass-through.
    #[must_use]
    pub(crate) const fn new(store: Option<AuditFileStore>) -> Self {
        Self { store }
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
        })
    }
}

pub(crate) struct AuditService<S> {
    service: Rc<S>,
    store: Option<AuditFileStore>,
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
        let client_ip = extract_client_ip(&req);

        let user = req
            .extensions()
            .get::<AuthenticatedUser>()
            .map_or_else(|| UNAUTHENTICATED.to_owned(), |u| u.username.clone());

        let start = Instant::now();
        let timestamp = OffsetDateTime::now_utc();
        let svc = self.service.clone();

        Box::pin(async move {
            let res = svc.call(req).await?;

            let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let status = res.status();

            let final_user = res
                .request()
                .extensions()
                .get::<AuthenticatedUser>()
                .map_or(user, |u| u.username.clone());

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

            let draft: AuditEventDraft = if status.is_success() || status.is_redirection() {
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

            store.enqueue(draft);

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

/// Extracts the client IP from the `X-Forwarded-For` header or the peer address.
fn extract_client_ip(req: &ServiceRequest) -> Option<String> {
    // TODO: XFF header can be spoofed by clients when there is no trusted reverse
    //       proxy in front of the KMS; validate against an IP allowlist in production.
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            if let Some(ip) = val.split(',').next() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return Some(ip.to_owned());
                }
            }
        }
    }
    req.peer_addr().map(|addr| addr.ip().to_string())
}

#[cfg(test)]
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
        use crate::core::audit::make_success_draft;
        use cosmian_kms_access::audit::AuditResult;
        use time::OffsetDateTime;

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
        use crate::core::audit::make_failure_draft;
        use cosmian_kms_access::audit::AuditResult;
        use time::OffsetDateTime;

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
}
