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
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::kmip_types::LinkType},
    cosmian_kms_crypto::openssl::{
        kmip_private_key_to_openssl,
        ocsp::{
            CrlReasonCode, NoncePolicy, OcspBuildConfig, OcspCertStatus, OcspStatusEntry,
            ParsedOcspQuery, build_ocsp_response, parse_ocsp_request, request_has_nonce,
            verify_delegated_responder_authorization, verify_issuer_hashes_match_ca,
        },
    },
};
use cosmian_logger::{debug, info};
use openssl::{sha::sha256, x509::X509};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::{
    config::NoncePolicyConfig,
    core::{KMS, operations::generate_crl::kmip_reason_to_crl_reason},
    error::KmsError,
    result::{KResult, KResultHelper},
};

// Content type per RFC 6960 Appendix C.
const CT_OCSP_RESPONSE: &str = "application/ocsp-response";

/// Maximum accepted length (bytes) of the base64url-encoded path segment on
/// `GET /ocsp/{encoded_request}`, checked before decoding.
///
/// RFC 6960 Appendix A intends GET only for requests small enough to fit
/// comfortably in a URL — in practice a handful of `SingleRequest` entries.
/// 4096 is generous headroom over any legitimate lightweight-profile request
/// while bounding the cost of decoding an attacker-controlled path segment.
const MAX_OCSP_GET_ENCODED_LEN: usize = 4096;

/// Base64url engine used to decode the `GET /ocsp/{encoded_request}` path
/// segment.
///
/// RFC 6960 Appendix A does not mandate whether the base64url encoding is
/// padded with `=`, and real-world OCSP clients disagree (e.g. `openssl ocsp`
/// and this project's own black-box test suite emit unpadded requests, while
/// other libraries emit padded ones). `DecodePaddingMode::Indifferent`
/// accepts both forms instead of rejecting well-formed requests with a
/// spurious 422 depending on the caller's padding choice.
static OCSP_GET_PATH_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Returns `true` if a base64url-encoded GET path segment of the given length
/// exceeds [`MAX_OCSP_GET_ENCODED_LEN`] and must be rejected before decoding.
const fn is_ocsp_get_path_too_long(encoded_len: usize) -> bool {
    encoded_len > MAX_OCSP_GET_ENCODED_LEN
}

type OcspResponseFuture<'a> = Pin<Box<dyn Future<Output = KResult<HttpResponse>> + 'a>>;
type OcspStatusFuture<'a> = Pin<Box<dyn Future<Output = KResult<OcspCertStatus>> + 'a>>;
type OcspSignerKey = openssl::pkey::PKey<openssl::pkey::Private>;
type OcspSignerMaterials = (X509, OcspSignerKey);
type OcspSignerFuture<'a> = Pin<Box<dyn Future<Output = KResult<OcspSignerMaterials>> + 'a>>;
type OcspCacheEntry = (Vec<u8>, Instant);
type OcspCache = RwLock<HashMap<String, OcspCacheEntry>>;

/// Upper bound on cached OCSP responses. The responder is unauthenticated, so the
/// cache must not grow with attacker-chosen serials; `unknown` responses are never
/// cached and expired entries are purged before this limit is enforced.
const MAX_OCSP_CACHE_ENTRIES: usize = 10_000;

/// In-memory OCSP response cache.
///
/// Map key: see [`ocsp_cache_key`] → `(signed DER bytes, expires_at Instant)`.
///
/// Only single-`CertID` requests are cached (a response covers exactly the
/// `CertID`s of its request). Requests that carry a nonce bypass the cache because
/// the nonce makes each response unique.
static OCSP_CACHE: LazyLock<OcspCache> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// Cache key for one `CertID`: the response echoes the requester's `CertID`
/// (hash algorithm and issuer hashes), so responses for different `CertID`
/// encodings of the same serial are not interchangeable. The key starts with
/// `"{ca_uid}:{serial_hex}:"` so [`evict_ocsp_cache_entry`] can drop every
/// encoding of a serial at once.
fn ocsp_cache_key(ca_uid: &str, query: &ParsedOcspQuery) -> String {
    format!(
        "{ca_uid}:{}:{}:{}:{}",
        query.serial_hex.to_ascii_uppercase(),
        query.hash_algorithm_nid,
        hex::encode(&query.issuer_name_hash),
        hex::encode(&query.issuer_key_hash)
    )
}

/// Evict a single entry from the in-memory OCSP response cache.
///
/// Called from `Revoke` (`crate::core::operations::revoke`) right after a
/// certificate's lifecycle state changes, so a relying party polling OCSP with
/// no nonce cannot continue to receive a cached `good` response for a
/// certificate that has just been revoked — the cache would otherwise only
/// self-correct after `ocsp_cache_ttl_secs` naturally elapses. A no-op if the
/// entry was never cached (e.g. OCSP disabled, or never queried).
pub(crate) async fn evict_ocsp_cache_entry(ca_uid: &str, serial_hex: &str) {
    let prefix = format!("{ca_uid}:{}:", serial_hex.to_ascii_uppercase());
    OCSP_CACHE
        .write()
        .await
        .retain(|key, _| !key.starts_with(&prefix));
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
///
/// RFC 6960 Appendix A recommends GET only for requests small enough to fit
/// comfortably in a URL (in practice a handful of certificate IDs at most).
/// `MAX_OCSP_GET_ENCODED_LEN` bounds the base64url-encoded path segment
/// *before* decoding, so an oversized path cannot force a wasted decode+parse
/// cycle ahead of the (already-enforced) `MAX_OCSP_QUERIES_PER_REQUEST` bound.
#[get("/ocsp/{encoded_request}")]
pub(crate) async fn get_ocsp(
    _req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KResult<HttpResponse> {
    let encoded = path.into_inner();
    if is_ocsp_get_path_too_long(encoded.len()) {
        debug!(
            len = encoded.len(),
            "OCSP GET request path exceeds MAX_OCSP_GET_ENCODED_LEN"
        );
        return Ok(build_malformed_request_response());
    }

    let request_der = OCSP_GET_PATH_ENGINE
        .decode(encoded.as_bytes())
        .map_err(|e| {
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

        // ── 5. Cache lookup (single-CertID requests only) ────────────────────────
        // A cached "good" entry may predate a CA compromise recorded after it was
        // signed; once the CA is compromised every entry must be freshly computed
        // (forced to `revoked`/`cACompromise` below) rather than served stale from
        // the cache, so the cache is unconditionally bypassed in that case.
        let cacheable_query = match queries.as_slice() {
            [query] if !has_nonce && !ca_compromised => Some(query),
            _ => None,
        };
        if let Some(query) = cacheable_query {
            let cache_key = ocsp_cache_key(ca_uid, query);
            if let Some((cached_der, expires_at)) = OCSP_CACHE.read().await.get(&cache_key) {
                // `expires_at` is when the cached response's nextUpdate passes.
                if Instant::now() < *expires_at {
                    debug!(serial = query.serial_hex, "OCSP cache HIT");
                    return Ok(build_ocsp_http_response(cached_der, ttl_secs));
                }
            }
        }

        // ── 5b. Build a status entry for every CertID ─────────────────────────────
        let mut entries: Vec<OcspStatusEntry> = Vec::with_capacity(queries.len());
        for query in &queries {
            let serial = &query.serial_hex;
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
        // `unknown` responses are not cached: they are what random-serial requests
        // produce, and caching them would let unauthenticated clients grow the map.
        if let (Some(query), [entry]) = (cacheable_query, entries.as_slice()) {
            if !matches!(entry.status, OcspCertStatus::Unknown) {
                let expires_at = Instant::now() + std::time::Duration::from_secs(ttl_secs);
                let mut cache = OCSP_CACHE.write().await;
                if cache.len() >= MAX_OCSP_CACHE_ENTRIES {
                    let now = Instant::now();
                    cache.retain(|_, (_, entry_expires_at)| *entry_expires_at > now);
                }
                if cache.len() < MAX_OCSP_CACHE_ENTRIES {
                    cache.insert(
                        ocsp_cache_key(ca_uid, query),
                        (resp_der.clone(), expires_at),
                    );
                }
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
/// | KMS State | OCSP status |
/// |---|---|
/// | `Active` / `PreActive` | good |
/// | `Compromised` / `Destroyed_Compromised` / `Deactivated` | revoked |
/// | `Destroyed` after a Revoke | revoked |
/// | `Destroyed` without Revoke / not found | unknown |
///
/// `revocationTime` and `revocationReason` come from the stored revocation
/// details (`deactivation_date`, `revocation_reason`), exactly as in the CRL, so
/// both sources agree and verifiers see when the certificate was actually revoked.
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
            Some((_uid, state, attributes)) => match state {
                State::Active | State::PreActive => OcspCertStatus::Good,
                // Mirrors `generate_crl::find_revoked_certificates`.
                State::Destroyed if attributes.revocation_reason.is_none() => {
                    OcspCertStatus::Unknown
                }
                State::Compromised
                | State::Destroyed_Compromised
                | State::Deactivated
                | State::Destroyed => OcspCertStatus::Revoked {
                    revocation_time: attributes
                        .deactivation_date
                        .unwrap_or_else(OffsetDateTime::now_utc),
                    reason: attributes
                        .revocation_reason
                        .as_ref()
                        .map(|r| kmip_reason_to_crl_reason(r.revocation_reason_code)),
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

        let signer_cert_der = match cert_owm.object() {
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object::Certificate(c) => {
                c.certificate_value.clone()
            }
            _ => {
                return Err(KmsError::InvalidRequest(format!(
                    "Object '{signer_cert_uid}' is not a certificate"
                )))
            }
        };

        // A delegated responder certificate (RFC 6960 §4.2.2.2) MUST carry the
        // `OCSPSigning` extended key usage and the `id-pkix-ocsp-nocheck` extension.
        // Enforced here — not just documented — so that `ocsp_responder_cert_uid`
        // cannot be pointed at an arbitrary, unqualified certificate/key pair (e.g. a
        // TLS server cert) already present in the KMS. Direct CA signing is exempt.
        if signer_cert_uid != ca_uid {
            verify_delegated_responder_authorization(&signer_cert_der).map_err(|e| {
                KmsError::InvalidRequest(format!(
                    "OCSP delegated responder certificate '{signer_cert_uid}' is not \
                     authorized to sign OCSP responses: {e}"
                ))
            })?;
        }

        let signer_cert = X509::from_der(&signer_cert_der)
            .map_err(|e| KmsError::InvalidRequest(format!("Cannot parse OCSP signer cert: {e}")))?;

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

        // The key may be wrapped at rest (server `key_encryption_key` or a user KEK).
        // The responder is unauthenticated, so unwrap on behalf of the key's owner.
        let signer_key_object =
            Box::pin(kms.get_unwrapped(key_owm.id(), key_owm.object(), key_owm.owner_id()))
                .await
                .context("unwrap OCSP signer private key")?;
        let signer_key = kmip_private_key_to_openssl(&signer_key_object).map_err(|e| {
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
    fn test_is_ocsp_get_path_too_long() {
        assert!(!is_ocsp_get_path_too_long(MAX_OCSP_GET_ENCODED_LEN));
        assert!(is_ocsp_get_path_too_long(MAX_OCSP_GET_ENCODED_LEN + 1));
    }

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

    fn query(serial: &str, nid: i32) -> ParsedOcspQuery {
        ParsedOcspQuery {
            serial_hex: serial.to_owned(),
            issuer_name_hash: vec![1, 2],
            issuer_key_hash: vec![3, 4],
            hash_algorithm_nid: nid,
        }
    }

    /// Responses echo the requester's `CertID`, so SHA-1 and SHA-256 `CertID`s for the
    /// same serial must not share a cache entry.
    #[test]
    fn test_ocsp_cache_key_includes_certid_encoding() {
        let sha1 = ocsp_cache_key("ca", &query("0A", openssl::nid::Nid::SHA1.as_raw()));
        let sha256 = ocsp_cache_key("ca", &query("0a", openssl::nid::Nid::SHA256.as_raw()));
        assert_ne!(sha1, sha256);
        assert!(sha1.starts_with("ca:0A:") && sha256.starts_with("ca:0A:"));
    }

    /// Revocation must evict every cached `CertID` encoding of the serial.
    #[tokio::test]
    async fn test_evict_removes_every_certid_encoding() {
        let far = Instant::now() + std::time::Duration::from_secs(3600);
        let keys = [
            ocsp_cache_key("evict-ca", &query("BEEF", openssl::nid::Nid::SHA1.as_raw())),
            ocsp_cache_key(
                "evict-ca",
                &query("BEEF", openssl::nid::Nid::SHA256.as_raw()),
            ),
        ];
        let other = ocsp_cache_key(
            "evict-ca",
            &query("BEEF01", openssl::nid::Nid::SHA1.as_raw()),
        );
        {
            let mut cache = OCSP_CACHE.write().await;
            for key in keys.iter().chain([&other]) {
                cache.insert(key.clone(), (vec![0], far));
            }
        }
        evict_ocsp_cache_entry("evict-ca", "beef").await;
        let cache = OCSP_CACHE.read().await;
        assert!(keys.iter().all(|k| !cache.contains_key(k)));
        assert!(
            cache.contains_key(&other),
            "a different serial must be kept"
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
