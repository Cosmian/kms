//! OpenTelemetry HTTP metrics middleware.
//!
//! Records `kms.http.requests.total`, `kms.http.request.duration`, and
//! `kms.active.connections` for every request that reaches the server.
//!
//! Must be placed as the **outermost** `App`-level wrap to correctly measure total latency.

use std::{borrow::Cow, sync::Arc, time::Instant};

use actix_web::{
    Error,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::{Next, from_fn},
};

use crate::core::OtelMetrics;

/// Creates the OpenTelemetry HTTP metrics middleware.
///
/// Records `kms.http.requests.total`, `kms.http.request.duration`, and
/// `kms.active.connections` for every request.
///
/// Pass `None` to install a zero-overhead pass-through (metrics disabled).
///
/// Place as the **outermost** `App`-level wrap to measure total latency.
pub(crate) fn otel_http_metrics_middleware<S, B>(
    metrics: Option<Arc<OtelMetrics>>,
) -> impl Transform<S, ServiceRequest, Response = ServiceResponse<B>, Error = Error, InitError = ()>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    from_fn(move |req: ServiceRequest, next: Next<B>| {
        let metrics = metrics.clone();
        // Snapshot method and normalized path before consuming the request.
        let method = match *req.method() {
            actix_web::http::Method::GET => Cow::Borrowed("GET"),
            actix_web::http::Method::POST => Cow::Borrowed("POST"),
            actix_web::http::Method::PUT => Cow::Borrowed("PUT"),
            actix_web::http::Method::DELETE => Cow::Borrowed("DELETE"),
            actix_web::http::Method::HEAD => Cow::Borrowed("HEAD"),
            actix_web::http::Method::OPTIONS => Cow::Borrowed("OPTIONS"),
            actix_web::http::Method::PATCH => Cow::Borrowed("PATCH"),
            _ => Cow::Owned(req.method().to_string()),
        };
        let path: &'static str = normalize_path(req.path());

        async move {
            if let Some(ref m) = metrics {
                m.increment_active_connections();
            }

            let start = Instant::now();
            let result = next.call(req).await;

            if let Some(ref m) = metrics {
                m.decrement_active_connections();

                let duration = start.elapsed().as_secs_f64();
                let status_code = result.as_ref().map_or_else(
                    |err| err.as_response_error().status_code(),
                    actix_web::dev::ServiceResponse::status,
                );
                let status = match status_code.as_u16() {
                    200 => Cow::Borrowed("200"),
                    201 => Cow::Borrowed("201"),
                    204 => Cow::Borrowed("204"),
                    400 => Cow::Borrowed("400"),
                    401 => Cow::Borrowed("401"),
                    403 => Cow::Borrowed("403"),
                    404 => Cow::Borrowed("404"),
                    405 => Cow::Borrowed("405"),
                    409 => Cow::Borrowed("409"),
                    422 => Cow::Borrowed("422"),
                    429 => Cow::Borrowed("429"),
                    500 => Cow::Borrowed("500"),
                    502 => Cow::Borrowed("502"),
                    503 => Cow::Borrowed("503"),
                    _ => Cow::Owned(status_code.as_str().to_owned()),
                };

                m.record_http_request(method.clone(), path, status.clone());
                m.record_http_request_duration(method, path, status, duration);
            }

            result
        }
    })
}

/// Maps a raw request path to a low-cardinality label for OTEL metrics.
///
/// Without normalization, hashed UI asset filenames (`/ui/assets/index-Ab3Cd.js`)
/// and per-key UID segments in REST paths would explode the metric cardinality.
///
/// The KMS route set is small and stable; static prefix matching is sufficient
/// and avoids any dependency on the actix-web pattern matcher at this layer.
fn normalize_path(path: &str) -> &'static str {
    // Exact matches for high-traffic single-path endpoints.
    match path {
        "/kmip/2_1" | "/kmip" => return "/kmip/2_1",
        "/version" => return "/version",
        "/health" => return "/health",
        _ => {}
    }

    // Prefix-based grouping for scoped route families.
    if path.starts_with("/access") {
        return "/access/{...}";
    }
    if path.starts_with("/google_cse") {
        return "/google_cse/{...}";
    }
    if path.starts_with("/ms_dke") {
        return "/ms_dke/{...}";
    }
    if path.starts_with("/aws") {
        return "/aws/{...}";
    }
    if path.starts_with("/azure") {
        return "/azure/{...}";
    }
    if path.starts_with("/v1/crypto") {
        return "/v1/crypto/{...}";
    }
    if path.starts_with("/ui") {
        return "/ui/{static}";
    }
    if path.starts_with("/swagger") || path.starts_with("/openapi") {
        return "/swagger/{...}";
    }
    if path.starts_with("/download-cli") {
        return "/download-cli";
    }
    // Some older KMIP clients use dot-notation (/kmip/2.1) instead of underscore.
    // Map to the same label so metrics are not silently bucketed as /other.
    if path.starts_with("/kmip/2.1") || path.starts_with("/kmip/1.") {
        return "/kmip/2_1";
    }

    "/other"
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, web};
    use opentelemetry_sdk::metrics::SdkMeterProvider;

    use super::{normalize_path, otel_http_metrics_middleware};
    use crate::core::OtelMetrics;

    #[test]
    fn test_normalize_exact_kmip() {
        assert_eq!(normalize_path("/kmip/2_1"), "/kmip/2_1");
        assert_eq!(normalize_path("/kmip"), "/kmip/2_1");
    }

    #[test]
    fn test_normalize_exact_endpoints() {
        assert_eq!(normalize_path("/version"), "/version");
        assert_eq!(normalize_path("/health"), "/health");
        assert_eq!(normalize_path("/download-cli"), "/download-cli");
    }

    #[test]
    fn test_normalize_prefix_groups() {
        assert_eq!(normalize_path("/access/owned"), "/access/{...}");
        assert_eq!(normalize_path("/access/accesses/abc123"), "/access/{...}");
        assert_eq!(normalize_path("/google_cse/rewrap"), "/google_cse/{...}");
        assert_eq!(normalize_path("/ms_dke/keys/mykey"), "/ms_dke/{...}");
        assert_eq!(
            normalize_path("/aws/kms/xks/v1/keys/abc/decrypt"),
            "/aws/{...}"
        );
        assert_eq!(normalize_path("/azure/keys/abc"), "/azure/{...}");
        assert_eq!(normalize_path("/v1/crypto/encrypt"), "/v1/crypto/{...}");
    }

    #[test]
    fn test_normalize_ui_assets() {
        assert_eq!(normalize_path("/ui/assets/index-Ab3Cd.js"), "/ui/{static}");
        assert_eq!(normalize_path("/ui/"), "/ui/{static}");
    }

    #[test]
    fn test_normalize_swagger() {
        assert_eq!(normalize_path("/swagger/ui"), "/swagger/{...}");
        assert_eq!(normalize_path("/openapi/kms.yaml"), "/swagger/{...}");
    }

    #[test]
    fn test_normalize_kmip_dot_notation() {
        // Older clients may use /kmip/2.1 (dot) instead of /kmip/2_1 (underscore).
        assert_eq!(normalize_path("/kmip/2.1"), "/kmip/2_1");
        assert_eq!(normalize_path("/kmip/1.4"), "/kmip/2_1");
    }

    #[test]
    fn test_normalize_unknown_falls_to_other() {
        assert_eq!(normalize_path("/unknown/deep/path"), "/other");
        assert_eq!(normalize_path("/"), "/other");
    }

    // middleware smoke tests

    fn make_test_metrics() -> Arc<OtelMetrics> {
        // No-op provider: instruments accept calls but do not export anything.
        // Same approach used by the existing tests in core/otel_metrics.rs.
        let provider = SdkMeterProvider::builder().build();
        Arc::new(OtelMetrics::new(provider).expect("Failed to create OtelMetrics"))
    }

    /// Verifies that the middleware passes requests through without error when
    /// a real `OtelMetrics` instance is configured (OTLP recording path is exercised).
    #[actix_web::test]
    async fn test_middleware_with_otel_metrics_passes_requests() {
        let app = actix_web::test::init_service(
            App::new()
                .wrap(otel_http_metrics_middleware(Some(make_test_metrics())))
                .service(web::resource("/kmip/2_1").to(|| async { "ok" })),
        )
        .await;

        let req = actix_web::test::TestRequest::post()
            .uri("/kmip/2_1")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    /// Verifies that `metrics = None` is a true no-op (no panic, request succeeds).
    #[actix_web::test]
    async fn test_middleware_noop_when_metrics_none() {
        let app = actix_web::test::init_service(
            App::new()
                .wrap(otel_http_metrics_middleware(None))
                .service(web::resource("/health").to(|| async { "ok" })),
        )
        .await;

        let req = actix_web::test::TestRequest::get()
            .uri("/health")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
