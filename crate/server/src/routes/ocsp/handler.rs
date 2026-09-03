//! OCSP (Online Certificate Status Protocol) responder handler.
//!
//! Implements RFC 6960 with:
//! - GET and POST HTTP transport (RFC 6960 Appendix A)
//! - Delegated OCSP signing key (RFC 6960 §4.2.2.2)
//! - Nonce support per RFC 9654 (supersedes RFC 8954)
//! - RFC 5019 lightweight profile HTTP cache headers
//! - Archive-cutoff extension (RFC 6960 §4.4.4)
//! - All 10 RFC 5280 revocation reason codes
//! - CA key compromise cascade (RFC 6960 §2.7)
//! - In-memory response cache to minimise signing key usage
//!
//! # Route layout
//! ```text
//! GET  /ocsp/{base64url-encoded-DER}   (RFC 6960 §A.1 — small requests ≤ 255 B)
//! POST /ocsp/                          (body: application/ocsp-request)
//! ```
//!
//! Both routes are **public** (no authentication required).  OCSP response content is
//! public information per RFC 6960 §2; requiring authentication would break relying-party
//! tooling (`openssl ocsp`, TLS stacks, browsers).

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Instant,
};

use actix_web::{
    HttpRequest, HttpResponse, get, post,
    web::{Bytes, Data, Path},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::kmip_types::LinkType},
    cosmian_kms_crypto::openssl::{
        kmip_private_key_to_openssl,
        ocsp::{
            CrlReasonCode, NoncePolicy, OcspBuildConfig, OcspCertStatus, OcspStatusEntry,
            build_ocsp_response, parse_ocsp_request, request_has_nonce,
            verify_issuer_hashes_match_ca,
        },
    },
};
use cosmian_logger::{debug, info};
use openssl::{sha::sha256, x509::X509};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::{
    config::NoncePolicyConfig,
    core::KMS,
    error::KmsError,
    result::{KResult, KResultHelper},
};

// Content type per RFC 6960 Appendix C.
const CT_OCSP_RESPONSE: &str = "application/ocsp-response";

type OcspResponseFuture<'a> = Pin<Box<dyn Future<Output = KResult<HttpResponse>> + 'a>>;
type OcspStatusFuture<'a> = Pin<Box<dyn Future<Output = KResult<OcspCertStatus>> + 'a>>;
type OcspSignerKey = openssl::pkey::PKey<openssl::pkey::Private>;
type OcspSignerMaterials = (X509, OcspSignerKey);
type OcspSignerFuture<'a> = Pin<Box<dyn Future<Output = KResult<OcspSignerMaterials>> + 'a>>;
type OcspCacheEntry = (Vec<u8>, Instant);
type OcspCache = RwLock<HashMap<String, OcspCacheEntry>>;

/// In-memory OCSP response cache.
///
/// Map key: `"{ca_uid}:{serial_hex}"` → `(signed DER bytes, expires_at Instant)`.
///
/// Requests that carry a nonce bypass the cache because the nonce makes each
/// response unique.
static OCSP_CACHE: LazyLock<OcspCache> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// Evict a single entry from the in-memory OCSP response cache.
///
/// Called from `Revoke` (`crate::core::operations::revoke`) right after a
/// certificate's lifecycle state changes, so a relying party polling OCSP with
/// no nonce cannot continue to receive a cached `good` response for a
/// certificate that has just been revoked — the cache would otherwise only
/// self-correct after `ocsp_cache_ttl_secs` naturally elapses. A no-op if the
/// entry was never cached (e.g. OCSP disabled, or never queried).
pub(crate) async fn evict_ocsp_cache_entry(ca_uid: &str, serial_hex: &str) {
    let cache_key = format!("{ca_uid}:{serial_hex}");
    OCSP_CACHE.write().await.remove(&cache_key);
}

// HTTP-date weekday / month name tables (RFC 7231 §7.1.1.1).
static HTTP_DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
static HTTP_MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// ─────────────────────────────────────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Handle an OCSP request submitted via HTTP GET.
///
/// The request DER is base64url-encoded in the path (RFC 6960 §A.1):
/// ```text
/// GET /ocsp/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
/// ```
#[get("/ocsp/{encoded_request}")]
pub(crate) async fn get_ocsp(
    _req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KResult<HttpResponse> {
    let encoded = path.into_inner();
    let request_der = URL_SAFE.decode(encoded.as_bytes()).map_err(|e| {
        KmsError::InvalidRequest(format!("Invalid base64url in OCSP GET path: {e}"))
    })?;
    info!("GET /ocsp/ ({} bytes)", request_der.len());
    handle_ocsp_request(&kms, &request_der).await
}

/// Handle an OCSP request submitted via HTTP POST.
///
/// The request body is a DER-encoded `OCSPRequest` with
/// `Content-Type: application/ocsp-request`.
#[post("/ocsp/")]
pub(crate) async fn post_ocsp(
    _req: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Bytes,
) -> KResult<HttpResponse> {
    info!("POST /ocsp/ ({} bytes)", body.len());
    handle_ocsp_request(&kms, &body).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Core logic
// ─────────────────────────────────────────────────────────────────────────────

/// Process a DER-encoded OCSP request and return a signed OCSP response.
///
/// Flow:
/// 1. Check `ocsp_enabled` — 404 when disabled.
/// 2. Parse request; verify issuer hashes match configured CA cert.
/// 3. Cascade check: if CA is compromised all leaf certs are `revoked`.
/// 4. Check in-memory cache (bypass when nonce present).
/// 5. Build status entries from KMS object states.
/// 6. Retrieve signer cert and private key.
/// 7. Sign `BasicResponse` via `cosmian_kms_crypto::openssl::ocsp`.
/// 8. Cache result; return with RFC 5019 headers.
fn handle_ocsp_request<'a>(kms: &'a KMS, request_der: &'a [u8]) -> OcspResponseFuture<'a> {
    Box::pin(async move {
        // ── 1. Enabled gate ─────────────────────────────────────────────────────
        if !kms.params.ocsp_enabled {
            return Ok(HttpResponse::NotFound().finish());
        }

        let ca_uid = kms.params.ocsp_ca_uid.as_deref().ok_or_else(|| {
            KmsError::InvalidRequest(
                "OCSP responder enabled but `ocsp_ca_uid` is not configured".to_owned(),
            )
        })?;

        let ttl_secs = kms.params.ocsp_cache_ttl_secs;
        let nonce_policy = map_nonce_policy(&kms.params.ocsp_nonce_policy);

        // ── 2. Parse request and verify issuer ──────────────────────────────────
        let queries = parse_ocsp_request(request_der)
            .map_err(|e| KmsError::InvalidRequest(format!("Malformed OCSP request: {e}")))?;

        // Determine once, up front, whether this specific request actually carries
        // a nonce. Both the "required" policy check below and the cache-bypass
        // decision (step 4) use this real per-request answer rather than an
        // overly conservative assumption based on policy alone — the latter would
        // defeat the response cache for every request under the documented
        // default policy (`optional`), even nonce-less ones.
        let request_carries_nonce = request_has_nonce(request_der)
            .map_err(|e| KmsError::InvalidRequest(format!("Malformed OCSP request: {e}")))?;

        // Nonce policy = required, but the request carries none — RFC 6960 §2.3
        // `malformedRequest`. This must be returned as a proper (unsigned) OCSP wire
        // response, not a generic HTTP error: real clients (e.g. `openssl ocsp`)
        // cannot parse anything other than a DER `OCSPResponse` and treat any other
        // body as a transport failure rather than a policy rejection.
        if nonce_policy == NoncePolicy::Required && !request_carries_nonce {
            return Ok(build_malformed_request_response());
        }

        let ca_owm = kms
            .database
            .retrieve_object(ca_uid)
            .await
            .context("retrieve CA certificate for OCSP")?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("OCSP CA certificate not found: {ca_uid}"))
            })?;

        let ca_der = match ca_owm.object() {
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object::Certificate(c) => {
            c.certificate_value.clone()
        }
        _ => {
            return Err(KmsError::InvalidRequest(format!(
                "Object '{ca_uid}' is not a certificate"
            )))
        }
    };

        let ca_cert = X509::from_der(&ca_der).map_err(|e| {
            KmsError::InvalidRequest(format!("Failed to parse CA certificate: {e}"))
        })?;

        let matches = verify_issuer_hashes_match_ca(&queries, &ca_cert)
            .map_err(|e| KmsError::CryptographicError(format!("Issuer hash check failed: {e}")))?;
        if !matches {
            return Ok(build_unauthorized_response());
        }

        // ── 3. CA key compromise cascade (RFC 6960 §2.7) ────────────────────────
        let ca_compromised = matches!(
            ca_owm.state(),
            State::Compromised | State::Destroyed_Compromised
        );

        // ── 4. Nonce detection ───────────────────────────────────────────────────
        // The cache is bypassed only when this specific request actually carries a
        // nonce that the configured policy would honor: `Ignore` never echoes a
        // nonce regardless of whether one was sent, so it never needs to defeat
        // the cache; `Optional`/`Required` echo a nonce when present, so a request
        // that truly carries one must always get a fresh, correctly-nonced
        // response. This keeps the cache effective for the common case of
        // nonce-less requests under the default `optional` policy, while still
        // guaranteeing a genuine nonce is never served from a stale cached entry.
        let has_nonce = nonce_policy != NoncePolicy::Ignore && request_carries_nonce;

        // ── 5. Build status entries with cache lookup ────────────────────────────
        let mut entries: Vec<OcspStatusEntry> = Vec::with_capacity(queries.len());
        // A cached "good" entry may predate a CA compromise recorded after it was
        // signed; once the CA is compromised every entry must be freshly computed
        // (forced to `revoked`/`cACompromise` below) rather than served stale from
        // the cache, so the cache is unconditionally bypassed in that case.
        let mut all_cached = !has_nonce && !ca_compromised;
        let mut cache_hit_responses: Vec<Vec<u8>> = Vec::new();

        for query in &queries {
            let serial = &query.serial_hex;
            let cache_key = format!("{ca_uid}:{serial}");

            if !has_nonce && !ca_compromised {
                let cache = OCSP_CACHE.read().await;
                if let Some((cached_der, expires)) = cache.get(&cache_key) {
                    if expires.elapsed().as_secs() < ttl_secs {
                        debug!(serial = serial, "OCSP cache HIT");
                        cache_hit_responses.push(cached_der.clone());
                        continue;
                    }
                }
            }
            all_cached = false;

            let status = if ca_compromised {
                OcspCertStatus::Revoked {
                    revocation_time: OffsetDateTime::now_utc(),
                    reason: Some(CrlReasonCode::CaCompromise),
                }
            } else {
                Box::pin(look_up_cert_status(kms, ca_uid, serial)).await?
            };

            entries.push(OcspStatusEntry {
                serial_hex: serial.clone(),
                status,
            });
        }

        if all_cached && !cache_hit_responses.is_empty() {
            debug!("OCSP: all serials served from cache");
            let cached_response = cache_hit_responses
                .first()
                .ok_or_else(|| KmsError::ServerError("OCSP cache unexpectedly empty".to_owned()))?;
            return Ok(build_ocsp_http_response(cached_response, ttl_secs));
        }

        // ── 6. Retrieve signer cert + key ────────────────────────────────────────
        let (signer_cert, signer_key) =
            Box::pin(retrieve_signer_cert_and_key(kms, ca_uid, &ca_cert)).await?;

        // ── 7. Sign BasicResponse ─────────────────────────────────────────────────
        let archive_cutoff = if kms.params.ocsp_archive_cutoff_secs > 0 {
            Some(kms.params.ocsp_archive_cutoff_secs)
        } else {
            None
        };

        let config = OcspBuildConfig {
            ttl_secs,
            nonce_policy,
            include_signer_cert: kms.params.ocsp_include_cert_chain,
            archive_cutoff_secs: archive_cutoff,
        };

        let resp_der = build_ocsp_response(
            request_der,
            &ca_cert,
            &signer_cert,
            &signer_key,
            &entries,
            &config,
        )
        .map_err(|e| KmsError::CryptographicError(format!("OCSP response build failed: {e}")))?;

        // ── 8. Cache + respond ────────────────────────────────────────────────────
        if !has_nonce && entries.len() == 1 {
            if let Some(entry) = entries.first() {
                let cache_key = format!("{ca_uid}:{}", entry.serial_hex);
                let expires_at = Instant::now() + std::time::Duration::from_secs(ttl_secs);
                OCSP_CACHE
                    .write()
                    .await
                    .insert(cache_key, (resp_der.clone(), expires_at));
            }
        }

        Ok(build_ocsp_http_response(&resp_der, ttl_secs))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Map the config-layer nonce policy to the crypto-crate enum.
const fn map_nonce_policy(config: &NoncePolicyConfig) -> NoncePolicy {
    match config {
        NoncePolicyConfig::Optional => NoncePolicy::Optional,
        NoncePolicyConfig::Required => NoncePolicy::Required,
        NoncePolicyConfig::Ignore => NoncePolicy::Ignore,
    }
}

/// Look up OCSP certificate status from KMS object state.
///
/// Status mapping per RFC 6960 §2.2:
///
/// | KMS State | OCSP status | Reason |
/// |---|---|---|
/// | Active / PreActive | good | — |
/// | Compromised / DestroyedCompromised | revoked | keyCompromise |
/// | Deactivated / Destroyed | revoked | cessationOfOperation |
/// | Not found | unknown | — |
fn look_up_cert_status<'a>(
    kms: &'a KMS,
    ca_uid: &'a str,
    serial_hex: &'a str,
) -> OcspStatusFuture<'a> {
    Box::pin(async move {
        let result = Box::pin(kms.database.find_certificate_by_serial(
            ca_uid,
            serial_hex,
            kms.vendor_id(),
        ))
        .await
        .context("find_certificate_by_serial")?;

        Ok(match result {
            None => OcspCertStatus::Unknown,
            Some((_uid, state)) => match state {
                State::Active | State::PreActive => OcspCertStatus::Good,
                State::Compromised | State::Destroyed_Compromised => OcspCertStatus::Revoked {
                    revocation_time: OffsetDateTime::now_utc(),
                    reason: Some(CrlReasonCode::KeyCompromise),
                },
                State::Deactivated | State::Destroyed => OcspCertStatus::Revoked {
                    revocation_time: OffsetDateTime::now_utc(),
                    reason: Some(CrlReasonCode::CessationOfOperation),
                },
            },
        })
    })
}

/// Retrieve the OCSP signing certificate and private key.
///
/// When `ocsp_responder_cert_uid` is set, the delegated responder cert+key are
/// used (RFC 6960 §4.2.2.2 authorized responder).  Otherwise the CA's own
/// cert+key are returned.
///
/// The private key is discovered by following the `PrivateKeyLink` attribute on
/// the signing certificate — the same pattern used by CRL signing (`generate_crl.rs`).
fn retrieve_signer_cert_and_key<'a>(
    kms: &'a KMS,
    ca_uid: &'a str,
    ca_cert: &'a X509,
) -> OcspSignerFuture<'a> {
    Box::pin(async move {
        let signer_cert_uid = kms
            .params
            .ocsp_responder_cert_uid
            .as_deref()
            .unwrap_or(ca_uid);

        // Retrieve the signing certificate.
        let cert_owm = kms
            .database
            .retrieve_object(signer_cert_uid)
            .await
            .context("retrieve OCSP signer certificate")?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!(
                    "OCSP signer certificate not found: {signer_cert_uid}"
                ))
            })?;

        // Refuse to perform a live signing operation with a *delegated* responder
        // certificate (RFC 6960 §4.2.2.2) that has itself independently been marked
        // compromised — an operator who configured a distinct `ocsp_responder_cert_uid`
        // specifically to avoid exercising the CA key never intended for the server to
        // silently keep using that delegate once it, too, is known-compromised.
        //
        // Deliberately does **not** apply when the signer *is* the CA's own key (no
        // delegated responder configured): RFC 6960 §2.7 requires the responder to keep
        // truthfully reporting `revoked`/`cACompromise` for every certificate the CA
        // issued precisely *because* the CA was compromised — refusing to sign at all in
        // that case would silence the cascade this feature exists to provide, which is
        // exercised end-to-end by `mise run test:ocsp` (step 7). Once a CA key is truly
        // compromised, an attacker holding it can already forge arbitrary responses
        // without the KMS's help, so continuing to use it here for an accurate,
        // already-forced `revoked` statement adds no meaningful additional exposure.
        if signer_cert_uid != ca_uid
            && matches!(
                cert_owm.state(),
                State::Compromised | State::Destroyed_Compromised
            )
        {
            return Err(KmsError::InvalidRequest(format!(
                "OCSP delegated responder certificate '{signer_cert_uid}' is marked \
                 Compromised; refusing to sign further OCSP responses with it. Configure a \
                 distinct, still-trustworthy `ocsp_responder_cert_uid` (or unset it to fall \
                 back to the CA's own key) to keep serving OCSP for this CA."
            )));
        }

        let signer_cert = match cert_owm.object() {
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object::Certificate(c) => {
                X509::from_der(&c.certificate_value).map_err(|e| {
                    KmsError::InvalidRequest(format!("Cannot parse OCSP signer cert: {e}"))
                })?
            }
            _ => {
                return Err(KmsError::InvalidRequest(format!(
                    "Object '{signer_cert_uid}' is not a certificate"
                )))
            }
        };

        // If signer == CA, return CA cert directly (we already have the CA X509).
        // Otherwise use the signer cert we just parsed.
        let signer_x509 = if signer_cert_uid == ca_uid {
            ca_cert.to_owned()
        } else {
            signer_cert
        };

        // Discover the linked private key via PrivateKeyLink attribute.
        let key_uid = cert_owm
            .attributes()
            .get_link(LinkType::PrivateKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "OCSP signer certificate '{signer_cert_uid}' has no PrivateKeyLink attribute"
                ))
            })?
            .to_string();

        let key_owm = kms
            .database
            .retrieve_object(&key_uid)
            .await
            .context("retrieve OCSP signer private key")?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("OCSP signer private key not found: {key_uid}"))
            })?;

        let signer_key = kmip_private_key_to_openssl(key_owm.object()).map_err(|e| {
            KmsError::CryptographicError(format!("Cannot load OCSP signing key: {e}"))
        })?;

        Ok((signer_x509, signer_key))
    })
}

/// Build the HTTP response carrying the DER-encoded OCSP response.
///
/// Adds RFC 5019 §5 cache control headers:
/// - `Cache-Control: max-age=N, public`
/// - `Expires: <nextUpdate as HTTP-date>`
/// - `Last-Modified: <thisUpdate as HTTP-date>`
fn build_ocsp_http_response(resp_der: &[u8], ttl_secs: u64) -> HttpResponse {
    let now = OffsetDateTime::now_utc();
    let next_update = now + time::Duration::seconds(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
    HttpResponse::Ok()
        .content_type(CT_OCSP_RESPONSE)
        .append_header(("Cache-Control", format!("max-age={ttl_secs}, public")))
        .append_header(("Expires", to_http_date(next_update)))
        .append_header(("Last-Modified", to_http_date(now)))
        .append_header(("ETag", format!("\"{}\"", etag_for(resp_der))))
        .body(resp_der.to_vec())
}

/// Compute a strong `ETag` validator (RFC 5019 §2.2.6, RFC 7232 §2.3) for an OCSP
/// response body: the hex-encoded SHA-256 digest of the DER bytes. Since the response
/// (and hence the `ETag`) only changes when its content changes, relying parties and
/// caching proxies can issue conditional `If-None-Match` requests to avoid re-fetching
/// an unchanged response.
fn etag_for(resp_der: &[u8]) -> String {
    use std::fmt::Write as _;
    sha256(resp_der).iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Format a UTC timestamp as an RFC 7231 IMF-fixdate string.
///
/// Example: `"Thu, 01 Jan 1970 00:00:00 GMT"`
fn to_http_date(dt: OffsetDateTime) -> String {
    let weekday_idx = usize::from(dt.weekday().number_days_from_sunday());
    let month_idx = usize::from(u8::from(dt.month())).saturating_sub(1);
    let day_name = HTTP_DAY_NAMES.get(weekday_idx).copied().unwrap_or("Thu");
    let month_name = HTTP_MONTH_NAMES.get(month_idx).copied().unwrap_or("Jan");
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        day_name,
        dt.day(),
        month_name,
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Return an OCSP `unauthorized` error response (minimal DER).
///
/// Per RFC 6960 §2.3 the responder returns `unauthorized` when it is not
/// authorised to provide status for the requested certificate
/// (i.e. issuer hashes in the request do not match our CA).
///
/// DER: `OCSPResponse { responseStatus: unauthorized (6) }`
/// = `SEQUENCE { ENUM { 6 } }` = `30 03 0a 01 06`
fn build_unauthorized_response() -> HttpResponse {
    static UNAUTHORIZED_DER: &[u8] = &[0x30, 0x03, 0x0a, 0x01, 0x06];
    HttpResponse::Ok()
        .content_type(CT_OCSP_RESPONSE)
        .body(UNAUTHORIZED_DER.to_vec())
}

/// Return an OCSP `malformedRequest` error response (minimal DER).
///
/// Per RFC 6960 §2.3 the responder returns `malformedRequest` when the request
/// does not satisfy a required syntactic/policy constraint — e.g. `ocsp_nonce_policy
/// = required` but the client's request carries no nonce (RFC 9654 §2.1).
///
/// This (like `unauthorized`) is an unsigned, top-level `OCSPResponse` error status:
/// it must be returned as HTTP 200 with an `application/ocsp-response` body, never
/// as a generic HTTP error — real clients only understand a DER `OCSPResponse`.
///
/// DER: `OCSPResponse { responseStatus: malformedRequest (1) }`
/// = `SEQUENCE { ENUM { 1 } }` = `30 03 0a 01 01`
fn build_malformed_request_response() -> HttpResponse {
    static MALFORMED_REQUEST_DER: &[u8] = &[0x30, 0x03, 0x0a, 0x01, 0x01];
    HttpResponse::Ok()
        .content_type(CT_OCSP_RESPONSE)
        .body(MALFORMED_REQUEST_DER.to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_map_nonce_policy_optional() {
        assert_eq!(
            map_nonce_policy(&NoncePolicyConfig::Optional),
            NoncePolicy::Optional
        );
    }

    #[test]
    fn test_map_nonce_policy_required() {
        assert_eq!(
            map_nonce_policy(&NoncePolicyConfig::Required),
            NoncePolicy::Required
        );
    }

    #[test]
    fn test_map_nonce_policy_ignore() {
        assert_eq!(
            map_nonce_policy(&NoncePolicyConfig::Ignore),
            NoncePolicy::Ignore
        );
    }

    #[test]
    fn test_unauthorized_response_content_type() {
        let resp = build_unauthorized_response();
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some(CT_OCSP_RESPONSE)
        );
    }

    #[test]
    fn test_malformed_request_response_content_type_and_status() {
        let resp = build_malformed_request_response();
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some(CT_OCSP_RESPONSE)
        );
    }

    #[test]
    fn test_ocsp_cache_key_format() {
        assert_eq!(
            format!("{ca}:{serial}", ca = "ca-123", serial = "0A1B2C"),
            "ca-123:0A1B2C"
        );
    }

    #[test]
    fn test_to_http_date_unix_epoch() {
        let s = to_http_date(OffsetDateTime::UNIX_EPOCH);
        assert!(s.contains("GMT"), "HTTP-date must end with GMT: {s}");
        assert!(s.contains("Jan"), "Epoch is January: {s}");
        assert!(s.contains("1970"), "Epoch year is 1970: {s}");
    }

    #[test]
    fn test_etag_is_stable_and_content_dependent() {
        let a = etag_for(b"response-bytes-a");
        let a_again = etag_for(b"response-bytes-a");
        let b = etag_for(b"response-bytes-b");
        assert_eq!(
            a, a_again,
            "ETag must be deterministic for identical bodies"
        );
        assert_ne!(a, b, "ETag must differ for different bodies");
        assert_eq!(a.len(), 64, "sha256 hex digest is 64 chars");
    }

    #[test]
    fn test_build_ocsp_http_response_sets_etag_header() {
        let resp = build_ocsp_http_response(b"fake-der-bytes", 86400);
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .expect("ETag header must be present (RFC 5019 §2.2.6)");
        assert!(etag.starts_with('"') && etag.ends_with('"'));
    }
}
