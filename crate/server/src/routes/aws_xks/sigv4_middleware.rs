//! API Token Authentication Middleware
//!
//! This module contains the middleware implementation for API token-based authentication.
//! It provides a separate authentication pipeline that can be used independently of
//! other authentication methods.
//!
//! Authentication: <https://github.com/aws/aws-kms-xksproxy-api-spec/blob/main/xks_proxy_api_spec.md#authentication>
//! Proxy Impl: <https://github.com/aws-samples/aws-kms-xks-proxy/tree/main>
//! Testing client: <https://github.com/aws-samples/aws-kms-xksproxy-test-client>

use std::{
    pin::Pin,
    rc::Rc,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};

use actix_web::{
    Error,
    body::{BoxBody, EitherBody},
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform},
    web::{Bytes, BytesMut},
};
use cosmian_logger::debug;
use futures::{
    Future, StreamExt,
    future::{Ready, err, ok},
};
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
use url::form_urlencoded;

use crate::{
    core::KMS,
    routes::aws_xks::{
        error::{XksErrorName, XksErrorReply},
        sigv4::{parse_sigv4_timestamp, verify_sigv4_request},
    },
};

const XKS_SIGV4_ALLOWED_MISMATCH_MINUTES: i64 = 5;

/// Largest `/aws` request body, read before `SigV4` authentication. Equal to the scope's JSON
/// extractor limit: XKS requests are a few KiB (4300-byte plaintext, 8192-byte AAD, base64).
pub(crate) const MAX_XKS_REQUEST_BODY: usize = 2 * 1024 * 1024;

/// Bounds the number of concurrent `SigV4` verification tasks running on the Tokio blocking
/// thread pool. Each unauthenticated XKS request can trigger CPU-heavy canonicalization and
/// hashing of a request body up to `MAX_XKS_REQUEST_BODY`; without a bound, an attacker could submit an
/// unbounded number of such requests and exhaust CPU and blocking-pool capacity (CWE-400:
/// Uncontrolled Resource Consumption). The previous synchronous verification path was
/// implicitly bounded by the number of Actix worker threads — this preserves an equivalent
/// bound, sized to the number of available CPUs.
static SIGV4_VERIFICATION_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    let permits = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    Semaphore::new(permits)
});

/// `Sigv4MWare` is an Actix web middleware that handles AWS Signature Version 4 (sigv4) protocol.
///
/// In Actix web, middlewares consist of two parts:
/// 1. A transformer (this struct), which is used during service configuration
/// 2. A middleware service that processes each request
///
/// This transformer is responsible for creating the middleware service with the necessary
/// configuration for API token authentication.
#[derive(Clone)]
pub struct Sigv4MWare {
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

impl Sigv4MWare {
    /// Creates a new `Sigv4MWare` with the given KMS server
    ///
    /// # Parameters
    /// * `kms_server` - The KMS server instance used for API token validation
    #[must_use]
    pub const fn new(kms_server: Arc<KMS>) -> Self {
        Self { kms_server }
    }
}

/// Implementation of the Transform trait, which is how Actix registers middleware
///
/// This trait defines how to create a new middleware service (`Sigv4Service`) from the
/// transformer. The middleware will be part of the Actix service pipeline.
impl<S, B> Transform<S, ServiceRequest> for Sigv4MWare
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = Sigv4Service<S, B>;

    /// Creates a new instance of the `Sigv4Service` service
    ///
    /// This is called once during application startup for each service
    /// that this middleware wraps. It passes the necessary configuration
    /// to the `Sigv4Service`.
    fn new_transform(&self, service: S) -> Self::Future {
        if self.kms_server.params.aws_xks_params.is_none() {
            tracing::error!(
                "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set"
            );
            return err(());
        }
        ok(Sigv4Service {
            service: Rc::new(service),
            kms_server: self.kms_server.clone(),
        })
    }
}

/// `Sigv4Service` is the actual middleware service that processes each request
///
/// This middleware validates API tokens for each incoming request.
pub struct Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    /// The next service in the middleware chain
    service: Rc<S>,
    /// Reference to the KMS server for API token authentication
    kms_server: Arc<KMS>,
}

/// Implementation of the Service trait, which defines how requests are processed
///
/// This is where the actual API token authentication logic happens for each incoming request.
impl<S, B> Service<ServiceRequest> for Sigv4Service<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    /// Checks if the middleware is ready to process a request
    ///
    /// This forwards the readiness check to the wrapped service.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    /// Processes each request by checking the signature v4
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let kms_server = self.kms_server.clone();

        Box::pin(async move {
            let params = kms_server.params.aws_xks_params.clone().ok_or_else(||
                actix_web::error::ErrorInternalServerError(
                    "AWS XKS Sigv4 middleware should not be enabled if the aws_xks_params are not set",
                )
            )?;
            let (actix_web_http_request, body): (actix_web::HttpRequest, actix_web::dev::Payload) =
                req.into_parts();

            let body_bytes = read_bounded_body(body, MAX_XKS_REQUEST_BODY).await?;

            let http_request = to_http_request(&actix_web_http_request, body_bytes.clone())?;

            // Canonicalization and body hashing run synchronously and scale with the request body
            // size (up to `MAX_XKS_REQUEST_BODY`), so running them directly on the Actix worker would let
            // a burst of large concurrent requests starve all HTTP workers (CWE-400). Offload the
            // whole verification to the blocking thread pool.
            //
            // Bound the number of concurrent verification tasks with a semaphore: an
            // unauthenticated caller could otherwise submit an unbounded number of large signed
            // (or invalid) requests and exhaust CPU/blocking-pool capacity even though each
            // individual task is offloaded (CWE-400).
            //
            // Acquire the permit *before* capturing `server_timestamp`: a request queued behind
            // the semaphore under load could otherwise be freshness-checked and signature-
            // validated against a timestamp captured well before its turn to run, letting it pass
            // the 5-minute anti-replay window using stale wall-clock time (CWE-367-style
            // time-of-check/time-of-use gap that weakens the replay control). Capturing the
            // timestamp only after the permit is granted ties both checks to the actual
            // processing time.
            let permit = SIGV4_VERIFICATION_PERMITS
                .acquire()
                .await
                .map_err(|error| {
                    actix_web::error::ErrorInternalServerError(format!(
                        "SigV4 verification semaphore unexpectedly closed: {error}"
                    ))
                })?;

            let server_timestamp = OffsetDateTime::now_utc();

            // 5-minute XKS anti-replay window (CWE-294).
            enforce_sigv4_request_freshness(&http_request, server_timestamp)?;

            let sigv4_result =
                tokio::task::spawn_blocking(move || verify_sigv4_request(&http_request, &params))
                    .await
                    .map_err(|join_err| {
                        actix_web::error::ErrorInternalServerError(format!(
                            "SigV4 verification task panicked: {join_err}"
                        ))
                    })?;
            drop(permit);

            if let Err(sigv4_err) = sigv4_result {
                tracing::warn!("SigV4 failure: {sigv4_err}");
                return Err(authentication_failed_error(format!(
                    "Signature v4 verification failed: {sigv4_err}"
                )));
            }

            // rebuild request with body_bytes and forward to next service
            let req = ServiceRequest::from_parts(actix_web_http_request, Payload::from(body_bytes));
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

fn authentication_failed_error(message: impl Into<String>) -> Error {
    XksErrorReply {
        errorName: XksErrorName::AuthenticationFailed,
        errorMessage: Some(message.into()),
    }
    .into()
}

/// Read the raw request body, failing as soon as it would exceed `limit` bytes (CWE-770).
async fn read_bounded_body(mut body: Payload, limit: usize) -> Result<Bytes, Error> {
    let mut bytes = BytesMut::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Failed to read the request body: {e}"))
        })?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(actix_web::error::ErrorPayloadTooLarge(format!(
                "AWS XKS request body exceeds {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes.freeze())
}

fn enforce_sigv4_request_freshness<B>(
    request: &http::Request<B>,
    server_timestamp: OffsetDateTime,
) -> Result<(), Error> {
    let request_timestamp = extract_sigv4_request_timestamp(request)?;
    // Parsed SigV4 timestamps have whole-second precision (the `YYYYMMDD'T'HHMMSS'Z'` format has
    // no fractional seconds), while `server_timestamp` retains subsecond precision. Floor the
    // server timestamp first so that requests exactly on the 5-minute boundary are not spuriously
    // rejected due to the sub-second remainder of `OffsetDateTime::now_utc()`.
    let server_timestamp = server_timestamp
        .replace_nanosecond(0)
        .unwrap_or(server_timestamp);
    let allowed_mismatch = Duration::minutes(XKS_SIGV4_ALLOWED_MISMATCH_MINUTES);
    let min_timestamp = server_timestamp
        .checked_sub(allowed_mismatch)
        .unwrap_or(server_timestamp);
    let max_timestamp = server_timestamp
        .checked_add(allowed_mismatch)
        .unwrap_or(server_timestamp);

    if request_timestamp < min_timestamp || request_timestamp > max_timestamp {
        return Err(authentication_failed_error(format!(
            "Signature v4 request timestamp exceeds the {XKS_SIGV4_ALLOWED_MISMATCH_MINUTES}-minute XKS replay window"
        )));
    }

    Ok(())
}

fn extract_sigv4_request_timestamp<B>(request: &http::Request<B>) -> Result<OffsetDateTime, Error> {
    // Same precedence as `verify_sigv4_request` for header-authenticated requests: the
    // `x-amz-date` header takes priority, then the `Date` header — both parsed as the basic SigV4
    // timestamp format (RFC 2822 is never used for SigV4). The `X-Amz-Date` query parameter is
    // only relevant to query-string (presigned URL) authentication, which the verifier rejects,
    // so it is checked last, as a fallback, rather than ahead of the `Date` header.
    if let Some(timestamp) = request.headers().get("x-amz-date") {
        return parse_sigv4_header_timestamp(timestamp.to_str().map_err(|error| {
            authentication_failed_error(format!(
                "Invalid SigV4 X-Amz-Date header encoding: {error}"
            ))
        })?);
    }

    if let Some(timestamp) = request.headers().get(http::header::DATE) {
        return parse_sigv4_header_timestamp(timestamp.to_str().map_err(|error| {
            authentication_failed_error(format!("Invalid SigV4 Date header encoding: {error}"))
        })?);
    }

    if let Some(query) = request.uri().query()
        && let Some((_, value)) =
            form_urlencoded::parse(query.as_bytes()).find(|(name, _)| name == "X-Amz-Date")
    {
        return parse_sigv4_header_timestamp(value.as_ref());
    }

    Err(authentication_failed_error(
        "Missing SigV4 request timestamp (expected X-Amz-Date or Date)",
    ))
}

fn parse_sigv4_header_timestamp(timestamp: &str) -> Result<OffsetDateTime, Error> {
    parse_sigv4_timestamp(timestamp).map_err(|error| {
        authentication_failed_error(format!("Invalid SigV4 X-Amz-Date value: {error}"))
    })
}

fn to_http_request(
    actix_req: &actix_web::HttpRequest,
    body: Bytes,
) -> Result<http::Request<Bytes>, actix_web::error::Error> {
    let method: http::Method = actix_req.method().as_str().parse().map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to parse HTTP method for Sigv4 validation: {e:?}"
        ))
    })?;
    let uri: http::Uri = actix_req.uri().to_string().parse().map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to parse HTTP URI for Sigv4 validation: {e:?}"
        ))
    })?;
    let version: http::Version = match actix_req.version() {
        actix_web::http::Version::HTTP_09 => http::Version::HTTP_09,
        actix_web::http::Version::HTTP_10 => http::Version::HTTP_10,
        actix_web::http::Version::HTTP_2 => http::Version::HTTP_2,
        actix_web::http::Version::HTTP_3 => http::Version::HTTP_3,
        _ => http::Version::HTTP_11,
    };

    let mut http_request_builder = http::request::Builder::new()
        .method(method)
        .uri(uri)
        .version(version);

    // If using the HTTP/2, the host header is missing in the request and must be added manually
    // for the signature to match
    let mut host_header_available = false;
    for (header_name, header_value) in actix_req.headers() {
        if header_name.as_str() == http::header::HOST.as_str() {
            host_header_available = true;
        }
        http_request_builder =
            http_request_builder.header(header_name.as_str(), header_value.as_bytes());
    }
    if !host_header_available {
        let host = actix_req.connection_info().host().to_owned();
        debug!("Sigv4 Middleware - Adding missing HOST header: {}", host);
        http_request_builder = http_request_builder.header(http::header::HOST, host.as_bytes());
    }
    // http_request_builder =
    //     http_request_builder.header(http::header::HOST, "localhost:9998".as_bytes());

    let http_request = http_request_builder.body(body).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to rebuild request for Sigv4 validation: {e:?}"
        ))
    })?;

    Ok(http_request)
}

#[cfg(test)]
mod tests {
    use actix_web::body::MessageBody;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn extract_sigv4_request_timestamp_prefers_header_value() {
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .header("X-Amz-Date", "20260903T120100Z")
            .header(http::header::DATE, "Thu, 03 Sep 2026 12:03:00 GMT")
            .body(Vec::<u8>::new())
            .map(|request| extract_sigv4_request_timestamp(&request));

        assert!(matches!(
            timestamp,
            Ok(Ok(value)) if value == datetime!(2026-09-03 12:01:00 UTC)
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_prefers_date_header_over_query() {
        // No `x-amz-date` header: the `Date` header must take precedence over the
        // `X-Amz-Date` query parameter, matching `verify_sigv4_request`'s precedence for
        // header-authenticated requests.
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .header(http::header::DATE, "20260903T120100Z")
            .body(Vec::<u8>::new())
            .map(|request| extract_sigv4_request_timestamp(&request));

        assert!(matches!(
            timestamp,
            Ok(Ok(value)) if value == datetime!(2026-09-03 12:01:00 UTC)
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_accepts_date_header_basic_sigv4_format() {
        // The `Date` header must be parsed using the basic SigV4 timestamp format, not RFC 2822.
        let timestamp = http::Request::builder()
            .uri("/")
            .header(http::header::DATE, "20260903T120000Z")
            .body(Vec::<u8>::new())
            .map(|request| extract_sigv4_request_timestamp(&request));

        assert!(matches!(
            timestamp,
            Ok(Ok(value)) if value == datetime!(2026-09-03 12:00:00 UTC)
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_supports_query_parameter() {
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .body(Vec::<u8>::new())
            .map(|request| extract_sigv4_request_timestamp(&request));

        assert!(matches!(
            timestamp,
            Ok(Ok(value)) if value == datetime!(2026-09-03 12:02:00 UTC)
        ));
    }

    #[test]
    fn parse_sigv4_header_timestamp_rejects_other_formats() {
        for timestamp in [
            "2026-09-03T12:00:00Z",
            "20260903T120000",
            "20260903T120000+0000",
            "20260903T120000Zx",
            "20261303T120000Z",
        ] {
            let error = parse_sigv4_header_timestamp(timestamp)
                .expect_err("timestamp must be rejected")
                .to_string();
            assert!(
                error.contains("Invalid SigV4 X-Amz-Date value"),
                "{timestamp}: {error}"
            );
        }
    }

    #[test]
    fn enforce_sigv4_request_freshness_allows_five_minute_boundary() {
        let result = http::Request::builder()
            .uri("/")
            .header("X-Amz-Date", "20260903T115500Z")
            .body(Vec::<u8>::new())
            .map(|request| {
                parse_sigv4_header_timestamp("20260903T120000Z").map(|server_timestamp| {
                    enforce_sigv4_request_freshness(&request, server_timestamp)
                })
            });

        assert!(matches!(
            result.map(|outcome| outcome.map(|freshness| freshness.is_ok())),
            Ok(Ok(true))
        ));
    }

    #[test]
    fn enforce_sigv4_request_freshness_rejects_stale_requests() {
        let reply = http::Request::builder()
            .uri("/")
            .header("X-Amz-Date", "20260903T115459Z")
            .body(Vec::<u8>::new())
            .map(|request| {
                parse_sigv4_header_timestamp("20260903T120000Z").map(|server_timestamp| {
                    enforce_sigv4_request_freshness(&request, server_timestamp)
                        .err()
                        .map(|error| {
                            error
                                .as_response_error()
                                .error_response()
                                .into_body()
                                .try_into_bytes()
                                .map(|body| String::from_utf8_lossy(&body).into_owned())
                        })
                })
            });

        assert!(matches!(
            reply,
            Ok(Ok(Some(Ok(body))))
                if body.contains("AuthenticationFailedException")
                    && body.contains("5-minute XKS replay window")
        ));
    }

    #[test]
    fn enforce_sigv4_request_freshness_floors_subsecond_server_timestamp() {
        // A request exactly 5 minutes old (whole seconds) must be accepted even when
        // `server_timestamp` carries a subsecond remainder (as `OffsetDateTime::now_utc()`
        // normally does); otherwise the documented inclusive 5-minute boundary is not honored.
        let result = parse_sigv4_header_timestamp("20260903T120000Z").map(|parsed| {
            let server_timestamp = parsed + Duration::milliseconds(500);
            http::Request::builder()
                .uri("/")
                .header("X-Amz-Date", "20260903T115500Z")
                .body(Vec::<u8>::new())
                .map(|request| enforce_sigv4_request_freshness(&request, server_timestamp))
        });

        assert!(matches!(result, Ok(Ok(Ok(())))));
    }

    fn stream_payload(chunks: Vec<Result<Bytes, actix_web::error::PayloadError>>) -> Payload {
        let stream: Pin<Box<dyn futures::Stream<Item = Result<Bytes, actix_web::error::PayloadError>>>> =
            Box::pin(futures::stream::iter(chunks));
        Payload::from(stream)
    }

    fn status_of(result: Result<Bytes, Error>) -> Option<actix_web::http::StatusCode> {
        result.err().map(|e| e.as_response_error().status_code())
    }

    #[tokio::test]
    async fn read_bounded_body_rejects_oversized_body() {
        let body = Payload::from(Bytes::from(vec![0_u8; MAX_XKS_REQUEST_BODY + 1]));
        assert_eq!(
            status_of(read_bounded_body(body, MAX_XKS_REQUEST_BODY).await),
            Some(actix_web::http::StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[tokio::test]
    async fn read_bounded_body_stops_before_reading_past_limit() {
        // The stream errors after the limit is crossed: a 413 (not a 400) proves that the stream
        // is no longer consumed once the cap is exceeded.
        let body = stream_payload(vec![
            Ok(Bytes::from_static(&[0; 8])),
            Ok(Bytes::from_static(&[0; 8])),
            Err(actix_web::error::PayloadError::Incomplete(None)),
        ]);
        assert_eq!(
            status_of(read_bounded_body(body, 10).await),
            Some(actix_web::http::StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[tokio::test]
    async fn read_bounded_body_propagates_stream_errors() {
        let body = stream_payload(vec![
            Ok(Bytes::from_static(b"ab")),
            Err(actix_web::error::PayloadError::Incomplete(None)),
        ]);
        assert_eq!(
            status_of(read_bounded_body(body, 10).await),
            Some(actix_web::http::StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn read_bounded_body_accepts_body_at_limit() {
        let body = Payload::from(Bytes::from_static(b"0123456789"));
        assert!(matches!(
            read_bounded_body(body, 10).await,
            Ok(bytes) if bytes == Bytes::from_static(b"0123456789")
        ));
    }
}
