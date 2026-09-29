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
    error::InternalError,
    http::StatusCode,
};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::Get,
    kmip_types::{KeyFormatType, UniqueIdentifier},
};
use cosmian_logger::debug;
use futures::{
    Future, StreamExt,
    future::{Ready, err, ok},
};
use scratchstack_aws_signature::{
    GetSigningKeyRequest, GetSigningKeyResponse, KSigningKey, NO_ADDITIONAL_SIGNED_HEADERS,
    SignatureOptions, sigv4_validate_request,
};
use tokio::sync::Semaphore;
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    middlewares::UserId,
    routes::aws_xks::error::{XksErrorName, XksErrorReply},
};

const XKS_SIGV4_ALLOWED_MISMATCH_MINUTES: i64 = 5;
const SIGV4_TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Bounds the number of concurrent `SigV4` verification tasks running on the Tokio blocking
/// thread pool. Each unauthenticated XKS request can trigger CPU-heavy canonicalization and
/// hashing of a request body up to 64 MB; without a bound, an attacker could submit an
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
            let access_key_id = params.sigv4_access_key_id;
            let access_key = params.sigv4_secret_access_key;

            let (actix_web_http_request, body): (actix_web::HttpRequest, actix_web::dev::Payload) =
                req.into_parts();

            let body_as_bytes = body
                .map(Result::unwrap_or_default)
                .fold(Vec::new(), |mut acc, chunk| async move {
                    acc.extend_from_slice(&chunk);
                    acc
                })
                .await;

            let http_request = to_http_request(&actix_web_http_request, &body_as_bytes)?;

            let access_key_id_for_svc = access_key_id.clone();
            let access_key_for_svc = access_key.clone();
            let mut get_signing_key_svc = SigningKeyService {
                access_key_id: access_key_id_for_svc,
                access_key: access_key_for_svc,
            };

            // Canonicalization and body hashing inside `sigv4_validate_request` run synchronously
            // and scale with the request body size (up to 64 MB for XKS), so running them
            // directly on the Actix worker would let a burst of large concurrent requests starve
            // all HTTP workers (CWE-400). Offload the whole verification call to the blocking
            // thread pool; `get_signing_key_svc` performs no actual I/O (pure HMAC derivation),
            // so driving its future with `block_on` inside the blocking task is sound and keeps
            // that CPU-bound work off the async reactor as well.
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

            let server_timestamp = Utc::now();

            // `scratchstack-aws-signature` 0.11.4 hard-codes a 15-minute SigV4 timestamp skew
            // and exposes no public override. Keep the previous 5-minute XKS anti-replay window
            // here to avoid CWE-294 replay-window widening until upstream provides a tunable API.
            enforce_sigv4_request_freshness(&http_request, server_timestamp)?;

            let region = params.region.clone();
            let service_name = params.service.clone();
            let runtime_handle = tokio::runtime::Handle::current();
            let sigv4_result = tokio::task::spawn_blocking(move || {
                runtime_handle.block_on(sigv4_validate_request(
                    http_request,
                    region.as_str(),
                    service_name.as_str(),
                    &mut get_signing_key_svc,
                    server_timestamp,
                    &NO_ADDITIONAL_SIGNED_HEADERS,
                    SignatureOptions::default(),
                ))
            })
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

            // rebuild request with body_as_bytes and forward to next service
            let req =
                ServiceRequest::from_parts(actix_web_http_request, Payload::from(body_as_bytes));
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

fn authentication_failed_error(message: impl Into<String>) -> Error {
    XksErrorReply {
        errorName: XksErrorName::AuthenticationFailedException,
        errorMessage: Some(message.into()),
    }
    .into()
}

fn enforce_sigv4_request_freshness(
    request: &http::Request<Vec<u8>>,
    server_timestamp: DateTime<Utc>,
) -> Result<(), Error> {
    let request_timestamp = extract_sigv4_request_timestamp(request)?;
    // Parsed SigV4 timestamps have whole-second precision (the `%Y%m%dT%H%M%SZ` format has no
    // fractional seconds), while `server_timestamp` retains subsecond precision. Floor the
    // server timestamp first so that requests exactly on the 5-minute boundary are not spuriously
    // rejected due to the sub-second remainder of `Utc::now()`.
    let server_timestamp = server_timestamp
        - Duration::nanoseconds(i64::from(server_timestamp.timestamp_subsec_nanos()));
    let allowed_mismatch = Duration::minutes(XKS_SIGV4_ALLOWED_MISMATCH_MINUTES);
    let min_timestamp = server_timestamp
        .checked_sub_signed(allowed_mismatch)
        .unwrap_or(server_timestamp);
    let max_timestamp = server_timestamp
        .checked_add_signed(allowed_mismatch)
        .unwrap_or(server_timestamp);

    if request_timestamp < min_timestamp || request_timestamp > max_timestamp {
        return Err(authentication_failed_error(format!(
            "Signature v4 request timestamp exceeds the {XKS_SIGV4_ALLOWED_MISMATCH_MINUTES}-minute XKS replay window"
        )));
    }

    Ok(())
}

fn extract_sigv4_request_timestamp(
    request: &http::Request<Vec<u8>>,
) -> Result<DateTime<Utc>, Error> {
    // Match `scratchstack-aws-signature`'s own precedence and parsing for header-authenticated
    // requests: the `x-amz-date` header takes priority, then the `Date` header — both parsed as
    // the basic SigV4 timestamp format (the validator's `parse_from_iso8601` accepts this format
    // for both headers; RFC 2822 is never used for SigV4). The `X-Amz-Date` query parameter is
    // only relevant to query-string (presigned URL) authentication, so it is checked last, as a
    // fallback, rather than ahead of the `Date` header.
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

    if let Some(query) = request.uri().query() {
        if let Some((_, value)) =
            form_urlencoded::parse(query.as_bytes()).find(|(name, _)| name == "X-Amz-Date")
        {
            return parse_sigv4_header_timestamp(value.as_ref());
        }
    }

    Err(authentication_failed_error(
        "Missing SigV4 request timestamp (expected X-Amz-Date or Date)",
    ))
}

fn parse_sigv4_header_timestamp(timestamp: &str) -> Result<DateTime<Utc>, Error> {
    NaiveDateTime::parse_from_str(timestamp, SIGV4_TIMESTAMP_FORMAT)
        .map(|parsed| parsed.and_utc())
        .map_err(|error| {
            authentication_failed_error(format!("Invalid SigV4 X-Amz-Date value: {error}"))
        })
}

/// A Tower `Service` that retrieves the `SigV4` signing key for a given access key ID.
///
/// XKS uses a single static key pair; this service validates the access key ID
/// and derives the HMAC signing key from the pre-configured secret.
struct SigningKeyService {
    access_key_id: String,
    access_key: String,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl tower_service::Service<GetSigningKeyRequest> for SigningKeyService {
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send>>;
    type Response = GetSigningKeyResponse;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
        let access_key_id = self.access_key_id.clone();
        let access_key = self.access_key.clone();
        Box::pin(async move {
            if access_key_id != req.access_key() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("Access key id {} not found", req.access_key()),
                    ),
                ));
            }
            let signing_key =
                derive_signing_key(&access_key, req.request_date(), req.region(), req.service())
                    .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
            // XKS does not use IAM principals — build response with signing key only
            GetSigningKeyResponse::builder()
                .signing_key(signing_key)
                .build()
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
        })
    }
}

/// Derives a `SigV4` `K_signing` key, supporting the full XKS-spec secret length range (43–64 chars).
// `KSecretKey::from_str` only accepts exactly M-4 chars (default M=44 → 40 chars); `KSigningKey`
// has no public constructor from raw bytes, so transmute is the only sound approach without
// modifying the upstream scratchstack library.
#[allow(unsafe_code)]
fn derive_signing_key(
    secret: &str,
    date: chrono::NaiveDate,
    region: &str,
    service: &str,
) -> Result<KSigningKey, hmac::digest::InvalidLength> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let hmac_raw = |key: &[u8], msg: &[u8]| -> Result<[u8; 32], hmac::digest::InvalidLength> {
        let mut mac = HmacSha256::new_from_slice(key)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().into())
    };

    let k_secret = format!("AWS4{secret}");
    let date_str = date.format("%Y%m%d").to_string();
    let k_date = hmac_raw(k_secret.as_bytes(), date_str.as_bytes())?;
    let k_region = hmac_raw(&k_date, region.as_bytes())?;
    let k_service = hmac_raw(&k_region, service.as_bytes())?;
    let k_signing = hmac_raw(&k_service, b"aws4_request")?;

    // SAFETY: `KSigningKey` is a single-field newtype over `[u8; 32]` with no padding;
    // its size and alignment are identical to `[u8; 32]`, making this transmute sound.
    Ok(unsafe { std::mem::transmute::<[u8; 32], KSigningKey>(k_signing) })
}

fn to_http_request(
    actix_req: &actix_web::HttpRequest,
    body: &[u8],
) -> Result<http::Request<Vec<u8>>, actix_web::error::Error> {
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

    let http_request = http_request_builder.body(body.to_vec()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!(
            "Failed to rebuild request for Sigv4 validation: {e:?}"
        ))
    })?;

    Ok(http_request)
}

/// Retrieves the AWS XKS sigv4 signing key from the KMS server
#[allow(dead_code)]
async fn get_aws_key(
    kms_server: &Arc<KMS>,
    sigv4_access_key_id: &str,
    sigv4_access_key_user: &str,
) -> Result<Zeroizing<Vec<u8>>, actix_web::error::InternalError<String>> {
    kms_server
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(
                    sigv4_access_key_id.to_owned(),
                )),
                key_format_type: Some(KeyFormatType::Raw),
                ..Default::default()
            },
            &UserId::from(sigv4_access_key_user),
        )
        .await
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?
        .object
        .key_block()
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key block from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?
        .secret_data_bytes()
        .map_err(|e| {
            InternalError::new(
                format!("Failed to get AWS XKS sigv4 key bytes from KMS: {e:?}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}

#[cfg(test)]
mod tests {
    use actix_web::body::MessageBody;

    use super::*;

    #[test]
    fn extract_sigv4_request_timestamp_prefers_header_value() {
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .header("X-Amz-Date", "20260903T120100Z")
            .header(http::header::DATE, "Thu, 03 Sep 2026 12:03:00 GMT")
            .body(Vec::new())
            .map(|request| extract_sigv4_request_timestamp(&request).map(|ts| ts.to_rfc3339()));

        assert!(matches!(
            timestamp,
            Ok(Ok(ref value)) if value == "2026-09-03T12:01:00+00:00"
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_prefers_date_header_over_query() {
        // No `x-amz-date` header: the `Date` header must take precedence over the
        // `X-Amz-Date` query parameter, matching `scratchstack-aws-signature`'s own
        // precedence for header-authenticated requests.
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .header(http::header::DATE, "20260903T120100Z")
            .body(Vec::new())
            .map(|request| extract_sigv4_request_timestamp(&request).map(|ts| ts.to_rfc3339()));

        assert!(matches!(
            timestamp,
            Ok(Ok(ref value)) if value == "2026-09-03T12:01:00+00:00"
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_accepts_date_header_basic_sigv4_format() {
        // The `Date` header must be parsed using the basic SigV4 timestamp format (as the
        // upstream validator does via `parse_from_iso8601`), not RFC 2822.
        let timestamp = http::Request::builder()
            .uri("/")
            .header(http::header::DATE, "20260903T120000Z")
            .body(Vec::new())
            .map(|request| extract_sigv4_request_timestamp(&request).map(|ts| ts.to_rfc3339()));

        assert!(matches!(
            timestamp,
            Ok(Ok(ref value)) if value == "2026-09-03T12:00:00+00:00"
        ));
    }

    #[test]
    fn extract_sigv4_request_timestamp_supports_query_parameter() {
        let timestamp = http::Request::builder()
            .uri("/?X-Amz-Date=20260903T120200Z")
            .body(Vec::new())
            .map(|request| extract_sigv4_request_timestamp(&request).map(|ts| ts.to_rfc3339()));

        assert!(matches!(
            timestamp,
            Ok(Ok(ref value)) if value == "2026-09-03T12:02:00+00:00"
        ));
    }

    #[test]
    fn enforce_sigv4_request_freshness_allows_five_minute_boundary() {
        let result = http::Request::builder()
            .uri("/")
            .header("X-Amz-Date", "20260903T115500Z")
            .body(Vec::new())
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
            .body(Vec::new())
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
        // `server_timestamp` carries a subsecond remainder (as `Utc::now()` normally does);
        // otherwise the documented inclusive 5-minute boundary is not honored.
        let result = parse_sigv4_header_timestamp("20260903T120000Z").map(|parsed| {
            let server_timestamp = parsed + Duration::milliseconds(500);
            http::Request::builder()
                .uri("/")
                .header("X-Amz-Date", "20260903T115500Z")
                .body(Vec::new())
                .map(|request| enforce_sigv4_request_freshness(&request, server_timestamp))
        });

        assert!(matches!(result, Ok(Ok(Ok(())))));
    }
}
