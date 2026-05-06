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
//!   paths `/google_cse/…` → `"GoogleCSE"`, etc.
//! * User identity: read from `AuthenticatedUser` in request extensions.  If
//!   absent (401 path) we record `"<unauthenticated>"`.
//! * Duration: measured as wall-clock elapsed from the moment the inner
//!   service `Future` is polled to completion.

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

const UNAUTHENTICATED: &str = "<unauthenticated>";

/// Factory struct — cheaply cloneable (wraps an `Option<AuditFileStore>` where
/// the store itself is already an `Arc` under the hood).
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
        // ── Fast path: audit disabled ─────────────────────────────────────
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

        // ── Capture per-request context ───────────────────────────────────
        let operation = extract_operation(req.path());
        let client_ip = extract_client_ip(&req);

        // Read user identity before the request is consumed; may be absent
        // (no auth configured, or auth will fail downstream).
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

            // Re-read user after authentication middlewares may have injected it
            // into the response extensions (actix propagates req extensions to resp).
            let final_user = res
                .request()
                .extensions()
                .get::<AuthenticatedUser>()
                .map_or(user, |u| u.username.clone());

            let draft: AuditEventDraft = if status.is_success() || status.is_redirection() {
                make_success_draft(
                    operation,
                    final_user,
                    None, // object_uid resolved post-deserialization — not available here
                    None, // algorithm — same
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
                    operation,
                    final_user,
                    None,
                    None,
                    client_ip,
                    duration_ms,
                    reason,
                )
            };

            // Override the timestamp with the one captured before the inner call
            // so the recorded time reflects request arrival, not response completion.
            let draft = AuditEventDraft { timestamp, ..draft };

            store.enqueue(draft);

            Ok(res.map_into_left_body())
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derives a human-readable operation name from the HTTP path.
fn extract_operation(path: &str) -> String {
    if path.contains("/kmip/") {
        "KMIP".to_owned()
    } else if path.contains("/google_cse") {
        "GoogleCSE".to_owned()
    } else if path.contains("/ms_dke") {
        "MsDKE".to_owned()
    } else if path.contains("/azure_ekm") {
        "AzureEKM".to_owned()
    } else if path.contains("/aws_xks") {
        "AwsXKS".to_owned()
    } else {
        // strip leading slash and use first segment
        path.trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("Unknown")
            .to_owned()
    }
}

/// Extracts the client IP from the `X-Forwarded-For` header or the peer address.
fn extract_client_ip(req: &ServiceRequest) -> Option<String> {
    // Prefer `X-Forwarded-For` (set by load balancers / reverse proxies)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            // XFF may contain a comma-separated list; take the first (client) entry
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
