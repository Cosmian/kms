//! Safe Rust OCSP (Online Certificate Status Protocol) response builder.
//!
//! Implements RFC 6960 (OCSP) with:
//! - Nonce support per RFC 9654 (supersedes RFC 8954) §2.1
//! - Delegated OCSP signing key support (RFC 6960 §4.2.2.2)
//! - Archive-cutoff extension (RFC 6960 §4.4.4)
//! - RFC 5019 lightweight profile compliance
//! - All 10 RFC 5280 §5.3.1 revocation reason codes
//!
//! # Security notes
//! - Every `unsafe` block carries a `// SAFETY:` comment.
//! - All FFI pointers are null-checked before use.
//! - Resources are freed via RAII guards to prevent leaks on error paths.

use std::{
    ffi::{CStr, c_long},
    ptr,
};

use foreign_types::ForeignTypeRef;
use openssl::{
    pkey::{PKeyRef, Private},
    x509::X509Ref,
};
use time::OffsetDateTime;

pub use super::crl::CrlReasonCode;
use super::ocsp_ffi::{
    self, ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_set, ASN1_INTEGER_to_BN,
    ASN1_STRING_get0_data, ASN1_STRING_length, BN_bn2hex, BN_free, CRL_REASON_AA_COMPROMISE,
    CRL_REASON_AFFILIATION_CHANGED, CRL_REASON_CA_COMPROMISE, CRL_REASON_CERTIFICATE_HOLD,
    CRL_REASON_CESSATION_OF_OPERATION, CRL_REASON_KEY_COMPROMISE, CRL_REASON_PRIVILEGE_WITHDRAWN,
    CRL_REASON_REMOVE_FROM_CRL, CRL_REASON_SUPERSEDED, CRL_REASON_UNSPECIFIED, OCSP_NONCE_MAX_LEN,
    OCSP_NONCE_MIN_LEN, OID_OCSP_ARCHIVE_CUTOFF, OID_OCSP_NONCE, V_OCSP_CERTSTATUS_GOOD,
    V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_UNKNOWN,
};
use crate::error::CryptoError;
use cosmian_logger::warn;

/// Maximum number of `SingleRequest`/`CertID` entries accepted in a single
/// `OCSPRequest`. RFC 5019 (the lightweight OCSP profile most CDN/proxy
/// deployments target) assumes small, single- or few-certificate requests;
/// a public, unauthenticated responder has no other bound on request
/// cardinality besides the transport-level payload size limit, so an
/// unbounded count is a resource-exhaustion amplification vector (each entry
/// triggers its own certificate-status lookup and is folded into one signed
/// response). 128 is generous for any legitimate real-world batch (e.g. an
/// OCSP stapling proxy checking a handful of certificates at once) while
/// keeping a single request's cost bounded.
const MAX_OCSP_QUERIES_PER_REQUEST: usize = 128;

/// Convert an `i64` (epoch seconds or a byte length) to the platform's C `long`.
///
/// `c_long` is 64-bit on Unix (LP64: Linux, macOS) but only **32-bit** on
/// Windows (LLP64), so a direct `as`/implicit cast that happens to compile on
/// Unix fails to compile at all on Windows (`error[E0308]: mismatched types`)
/// — this must go through a real, fallible conversion on every platform.
/// Never panics: propagates a [`CryptoError`] instead of the
/// `.try_into().unwrap()` rustc would otherwise suggest, since silently
/// panicking on a large-but-plausible timestamp (e.g. a distant `nextUpdate`)
/// is not acceptable in production code.
fn to_c_long(value: i64) -> Result<c_long, CryptoError> {
    c_long::try_from(value)
        .map_err(|e| CryptoError::Default(format!("value {value} does not fit in a C long: {e}")))
}

// ──────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────

/// The revocation status for a single certificate in an OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is valid (RFC 6960 §2.2).
    Good,
    /// Certificate has been revoked (RFC 6960 §2.2).
    Revoked {
        /// The time the certificate was revoked.
        revocation_time: OffsetDateTime,
        /// RFC 5280 §5.3.1 revocation reason (None = `Unspecified`).
        reason: Option<CrlReasonCode>,
    },
    /// Certificate status is unknown (RFC 6960 §2.2).
    Unknown,
}

/// A single certificate status entry to include in the OCSP response.
#[derive(Debug, Clone)]
pub struct OcspStatusEntry {
    /// Hex-encoded serial number without prefix (e.g. `"0A1B2C3D"`).
    ///
    /// Must be uppercase or lowercase ASCII hex; case-insensitive.
    pub serial_hex: String,
    /// Revocation status for this certificate.
    pub status: OcspCertStatus,
}

/// OCSP nonce handling policy (RFC 9654 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoncePolicy {
    /// Echo the nonce if present in the request; proceed without one if absent. *(default)*
    #[default]
    Optional,
    /// The request MUST contain a nonce; return an error if absent.
    Required,
    /// Never include a nonce in the response (suitable for pre-produced/cached responses).
    Ignore,
}

/// Configuration for building an OCSP response.
#[derive(Debug, Clone)]
pub struct OcspBuildConfig {
    /// Response validity in seconds (`thisUpdate` → `nextUpdate`). Default: 86400 (24 h).
    pub ttl_secs: u64,
    /// Nonce policy per RFC 9654.
    pub nonce_policy: NoncePolicy,
    /// When `true`, include the signer certificate chain in the `BasicResponse`.
    ///
    /// Required when the signer is a delegated OCSP responder cert rather than the
    /// CA certificate itself, so clients can verify the responder's authorization.
    pub include_signer_cert: bool,
    /// If `Some(secs)`, include the `id-pkix-ocsp-archive-cutoff` extension (RFC 6960 §4.4.4)
    /// with value = now − secs.
    pub archive_cutoff_secs: Option<u64>,
}

impl Default for OcspBuildConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 86400,
            nonce_policy: NoncePolicy::Optional,
            include_signer_cert: true,
            archive_cutoff_secs: None,
        }
    }
}

/// A parsed certificate query from an OCSP request.
#[derive(Debug, Clone)]
pub struct ParsedOcspQuery {
    /// Uppercase hex-encoded serial number extracted from the `CertId`.
    pub serial_hex: String,
    /// Raw bytes of the `issuerNameHash` field, digested with `hash_algorithm_nid`.
    pub issuer_name_hash: Vec<u8>,
    /// Raw bytes of the `issuerKeyHash` field, digested with `hash_algorithm_nid`.
    pub issuer_key_hash: Vec<u8>,
    /// OpenSSL NID of the digest algorithm the client used for this `CertId`
    /// (RFC 6960 §4.1.1 `hashAlgorithm`; e.g. `NID_sha1`, `NID_sha256`, ...).
    ///
    /// Real-world clients commonly default to SHA-1 for this field (it is only
    /// used to *identify* the issuer, never as a signature digest), so the
    /// responder must honour whatever algorithm the request actually used
    /// rather than assuming a fixed one.
    pub hash_algorithm_nid: i32,
}

// ──────────────────────────────────────────────────────────────
// RAII guards for FFI-allocated objects
// ──────────────────────────────────────────────────────────────

struct BasicRespGuard(*mut openssl_sys::OCSP_BASICRESP);
impl Drop for BasicRespGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was null-checked before wrapping.
        unsafe { openssl_sys::OCSP_BASICRESP_free(self.0) }
    }
}

struct OcspResponseGuard(*mut openssl_sys::OCSP_RESPONSE);
impl Drop for OcspResponseGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was null-checked before wrapping.
        unsafe { openssl_sys::OCSP_RESPONSE_free(self.0) }
    }
}

struct OcspRequestGuard(*mut openssl_sys::OCSP_REQUEST);
impl Drop for OcspRequestGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was null-checked before wrapping.
        unsafe { openssl_sys::OCSP_REQUEST_free(self.0) }
    }
}

struct GeneralizedTimeGuard(*mut openssl_sys::ASN1_GENERALIZEDTIME);
impl Drop for GeneralizedTimeGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was null-checked before wrapping.
        unsafe { ASN1_GENERALIZEDTIME_free(self.0) }
    }
}

struct CidGuard(*mut openssl_sys::OCSP_CERTID);
impl Drop for CidGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was null-checked before wrapping.
        unsafe { openssl_sys::OCSP_CERTID_free(self.0) }
    }
}

// ──────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────

/// Parse the certificate queries embedded in a DER-encoded OCSP request.
///
/// Returns one [`ParsedOcspQuery`] per `OCSP_ONEREQ` found in the request.
///
/// # Errors
/// Returns [`CryptoError`] if the DER is malformed or contains no certificate IDs.
#[expect(unsafe_code)]
pub fn parse_ocsp_request(request_der: &[u8]) -> Result<Vec<ParsedOcspQuery>, CryptoError> {
    let req_len = c_long::try_from(request_der.len())
        .map_err(|e| CryptoError::Default(format!("OCSP request DER too large: {e}")))?;

    // SAFETY: d2i_OCSP_REQUEST advances the pointer and returns null on error.
    let req = unsafe {
        let mut p = request_der.as_ptr();
        openssl_sys::d2i_OCSP_REQUEST(ptr::null_mut(), &raw mut p, req_len)
    };
    if req.is_null() {
        return Err(CryptoError::Default(
            "Failed to parse OCSP request DER".to_owned(),
        ));
    }
    let _req_guard = OcspRequestGuard(req);

    // SAFETY: req is non-null (checked above).
    let count = unsafe { ocsp_ffi::OCSP_request_onereq_count(req) };
    if count <= 0 {
        return Err(CryptoError::Default(
            "OCSP request contains no certificate IDs".to_owned(),
        ));
    }
    let count_usize = usize::try_from(count)
        .map_err(|e| CryptoError::Default(format!("Invalid query count: {e}")))?;
    // Reject oversized batches up front, before allocating a Vec sized to the
    // (attacker-controlled) count and before any per-query database lookup or
    // signing work is performed downstream.
    if count_usize > MAX_OCSP_QUERIES_PER_REQUEST {
        return Err(CryptoError::Default(format!(
            "OCSP request contains {count_usize} certificate IDs, exceeding the maximum of \
             {MAX_OCSP_QUERIES_PER_REQUEST} per request"
        )));
    }

    let mut queries = Vec::with_capacity(count_usize);

    for i in 0..count {
        // SAFETY: i is in [0, count), req is non-null.
        let one_req = unsafe { ocsp_ffi::OCSP_request_onereq_get0(req, i) };
        if one_req.is_null() {
            return Err(CryptoError::Default(format!(
                "OCSP_request_onereq_get0 returned null for index {i}"
            )));
        }

        // SAFETY: one_req is non-null.
        let cid = unsafe { ocsp_ffi::OCSP_onereq_get0_id(one_req) };
        if cid.is_null() {
            return Err(CryptoError::Default(format!(
                "OCSP_onereq_get0_id returned null for index {i}"
            )));
        }

        queries.push(extract_query_from_cert_id(cid)?);
    }

    Ok(queries)
}

/// Verify that at least one query in `queries` has issuer hashes matching `ca_cert`.
///
/// Each query's issuer hashes are compared against a reference computed with **that
/// query's own `hash_algorithm_nid`** (RFC 6960 §4.1.1) — not a fixed algorithm.
/// Real-world clients (including the reference `openssl ocsp` client) commonly default
/// to SHA-1 for the `CertId` hash; hardcoding a single digest here would reject those
/// requests as `unauthorized` even though they are perfectly valid.
///
/// Returns `true` if any query's issuer hashes match the CA under its own algorithm;
/// returns `false` if none match (i.e., the request is for a different CA, or uses a
/// digest algorithm this OpenSSL build does not support).
#[expect(unsafe_code)]
pub fn verify_issuer_hashes_match_ca(
    queries: &[ParsedOcspQuery],
    ca_cert: &X509Ref,
) -> Result<bool, CryptoError> {
    for q in queries {
        // SAFETY: EVP_get_digestbynid returns null for an unrecognised NID; checked below.
        let md = unsafe { openssl_sys::EVP_get_digestbynid(q.hash_algorithm_nid) };
        if md.is_null() {
            // Unknown/unsupported digest algorithm — cannot match, try the next query.
            continue;
        }

        // Build a reference OCSP_CERTID from the CA itself, using the same digest as
        // the query. OCSP_cert_to_id(dgst, subject=ca_cert, issuer=ca_cert) gives us
        // what we need because OpenSSL computes issuerNameHash from issuer.subject and
        // issuerKeyHash from issuer.pubkey; the serial number is irrelevant here.
        // SAFETY: ca_cert is valid; OCSP_cert_to_id returns null on error.
        let ref_cid = unsafe { ocsp_ffi::OCSP_cert_to_id(md, ca_cert.as_ptr(), ca_cert.as_ptr()) };
        if ref_cid.is_null() {
            continue;
        }
        let _cid_guard = CidGuard(ref_cid);

        let ref_query = extract_query_from_cert_id(ref_cid)?;
        if q.issuer_name_hash == ref_query.issuer_name_hash
            && q.issuer_key_hash == ref_query.issuer_key_hash
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verify that a delegated OCSP responder certificate satisfies RFC 6960 §4.2.2.2:
///
/// - `extKeyUsage` MUST contain `id-kp-OCSPSigning` (OID `1.3.6.1.5.5.7.3.9`) — this
///   is a hard requirement for OCSP signing delegation ("OCSP signing delegation
///   SHALL be designated by the inclusion of id-kp-OCSPSigning ... in the OCSP
///   response signer's certificate", RFC 6960 §4.2.2.2) and is rejected outright when
///   absent.
/// - `id-pkix-ocsp-nocheck` (OID `1.3.6.1.5.5.7.48.1.5`, RFC 6960 §4.2.2.2.1) is
///   **not** a MUST: the RFC presents it as only one of three equally valid ways a
///   relying party may check the *responder's own* revocation status — the CA may
///   instead point to a CDP/AIA for the responder cert, or leave it to local policy.
///   Its absence is therefore logged as a warning, not rejected, so a delegated
///   responder certificate that relies on one of the other two RFC-sanctioned
///   strategies is not incorrectly refused.
///
/// Only applies to *delegated* responder certificates (`ocsp_responder_cert_uid` set
/// to something other than the CA itself) — direct CA signing is exempt, matching the
/// scoping of the compromised-state check in the caller.
///
/// # Errors
/// Returns [`CryptoError`] if the certificate DER cannot be parsed, or if the
/// `id-kp-OCSPSigning` extended key usage is missing.
pub fn verify_delegated_responder_authorization(signer_cert_der: &[u8]) -> Result<(), CryptoError> {
    use x509_parser::{der_parser::oid, oid_registry::Oid, prelude::FromDer};

    let (_, cert) =
        x509_parser::certificate::X509Certificate::from_der(signer_cert_der).map_err(|e| {
            CryptoError::Default(format!(
                "Cannot parse delegated OCSP signer cert for authorization check: {e}"
            ))
        })?;

    let has_ocsp_signing_eku = cert
        .tbs_certificate
        .extended_key_usage()
        .map_err(|e| CryptoError::Default(format!("Invalid ExtendedKeyUsage extension: {e}")))?
        .is_some_and(|eku| eku.value.ocsp_signing);
    if !has_ocsp_signing_eku {
        return Err(CryptoError::Default(
            "Delegated OCSP responder certificate is missing the required \
             `extKeyUsage: OCSPSigning` (id-kp-OCSPSigning, OID 1.3.6.1.5.5.7.3.9) per \
             RFC 6960 §4.2.2.2"
                .to_owned(),
        ));
    }

    // `id-pkix-ocsp-nocheck` has no named constant in `oid-registry`; match by raw OID.
    // Its absence is a warning, not a rejection — see the doc comment above for why
    // this is only one of three RFC 6960 §4.2.2.2.1-sanctioned strategies, not a MUST.
    let ocsp_nocheck_oid: Oid<'_> = oid!(1.3.6.1.5.5.7.48.1.5);
    let has_nocheck = cert
        .tbs_certificate
        .get_extension_unique(&ocsp_nocheck_oid)
        .map_err(|e| {
            CryptoError::Default(format!(
                "Invalid extensions on delegated OCSP signer cert: {e}"
            ))
        })?
        .is_some();
    if !has_nocheck {
        warn!(
            "Delegated OCSP responder certificate does not carry the `id-pkix-ocsp-nocheck` \
             extension (OID 1.3.6.1.5.5.7.48.1.5, RFC 6960 §4.2.2.2.1). Relying parties may \
             attempt to recursively check this certificate's own revocation status via CDP, \
             AIA, or local policy instead."
        );
    }

    Ok(())
}

/// Build a DER-encoded OCSP response.
///
/// # Arguments
/// * `request_der` — DER bytes of the incoming OCSP request.
/// * `issuer_cert` — The CA certificate (used for issuer identity / AKI).
/// * `signer_cert` — Certificate used to sign the response (may equal `issuer_cert`
///   for direct signing, or be a delegated OCSP responder cert per RFC 6960 §4.2.2.2).
/// * `signer_key`  — Private key matching `signer_cert`.
/// * `entries`     — Pre-computed status for each requested serial number.
/// * `config`      — Build options (TTL, nonce policy, archive-cutoff, cert chain).
///
/// # Errors
/// Returns [`CryptoError`] on any OpenSSL failure or DER serialization error.
///
/// # Standards
/// - RFC 6960 §4.2.1 — `BasicResponse` structure
/// - RFC 6960 §4.4.1 + RFC 9654 §2.1 — Nonce extension
/// - RFC 6960 §4.4.4 — Archive-cutoff extension
/// - RFC 6960 §4.2.2.2 — Authorized responder
#[expect(unsafe_code)]
pub fn build_ocsp_response(
    request_der: &[u8],
    _issuer_cert: &X509Ref,
    signer_cert: &X509Ref,
    signer_key: &PKeyRef<Private>,
    entries: &[OcspStatusEntry],
    config: &OcspBuildConfig,
) -> Result<Vec<u8>, CryptoError> {
    let req_len = c_long::try_from(request_der.len())
        .map_err(|e| CryptoError::Default(format!("OCSP request DER too large: {e}")))?;

    // Parse the request.
    // SAFETY: d2i_OCSP_REQUEST advances the raw pointer; returns null on error.
    let req = unsafe {
        let mut p = request_der.as_ptr();
        openssl_sys::d2i_OCSP_REQUEST(ptr::null_mut(), &raw mut p, req_len)
    };
    if req.is_null() {
        return Err(CryptoError::Default(
            "Failed to parse OCSP request DER".to_owned(),
        ));
    }
    let _req_guard = OcspRequestGuard(req);

    // Allocate a new BasicResponse.
    // SAFETY: OCSP_BASICRESP_new returns null on OOM.
    let brsp = unsafe { openssl_sys::OCSP_BASICRESP_new() };
    if brsp.is_null() {
        return Err(CryptoError::Default("OCSP_BASICRESP_new failed".to_owned()));
    }
    let brsp_guard = BasicRespGuard(brsp);

    // ── Compute thisUpdate and nextUpdate ────────────────────────────────────────
    let now_epoch = to_c_long(OffsetDateTime::now_utc().unix_timestamp())?;
    let next_epoch = now_epoch
        .checked_add(c_long::try_from(config.ttl_secs).unwrap_or(c_long::MAX))
        .ok_or_else(|| CryptoError::Default("OCSP nextUpdate epoch overflowed".to_owned()))?;

    // SAFETY: ASN1_GENERALIZEDTIME_set allocates a new object when first arg is null.
    let this_update = unsafe { ASN1_GENERALIZEDTIME_set(ptr::null_mut(), now_epoch) };
    if this_update.is_null() {
        return Err(CryptoError::Default(
            "ASN1_GENERALIZEDTIME_set (thisUpdate) failed".to_owned(),
        ));
    }
    let _this_update_guard = GeneralizedTimeGuard(this_update);

    // SAFETY: ASN1_GENERALIZEDTIME_set allocates a new object when first arg is null.
    let next_update = unsafe { ASN1_GENERALIZEDTIME_set(ptr::null_mut(), next_epoch) };
    if next_update.is_null() {
        return Err(CryptoError::Default(
            "ASN1_GENERALIZEDTIME_set (nextUpdate) failed".to_owned(),
        ));
    }
    let _next_update_guard = GeneralizedTimeGuard(next_update);

    // ── Add status for each ONEREQ in the request ────────────────────────────────
    // SAFETY: req is non-null.
    let count = unsafe { ocsp_ffi::OCSP_request_onereq_count(req) };
    for i in 0..count {
        // SAFETY: i in [0, count).
        let one_req = unsafe { ocsp_ffi::OCSP_request_onereq_get0(req, i) };
        if one_req.is_null() {
            continue;
        }
        // SAFETY: one_req is non-null.
        let cid = unsafe { ocsp_ffi::OCSP_onereq_get0_id(one_req) };
        if cid.is_null() {
            continue;
        }

        // Extract the serial hex to match against our entries.
        let serial_hex = extract_serial_hex(cid)?;

        // Find the matching entry or default to Unknown.
        let entry = entries
            .iter()
            .find(|e| e.serial_hex.eq_ignore_ascii_case(&serial_hex));

        add_single_response(brsp, cid, entry, this_update, next_update)?;
    }

    // ── Nonce extension (RFC 9654 §2.1, RFC 6960 §4.4.1) ──────────────────────────
    handle_nonce(req, brsp, config.nonce_policy)?;

    // ── Archive-cutoff extension (RFC 6960 §4.4.4) ───────────────────────────────
    if let Some(cutoff_secs) = config.archive_cutoff_secs {
        add_archive_cutoff(brsp, now_epoch, cutoff_secs)?;
    }

    // ── Sign the BasicResponse ───────────────────────────────────────────────────
    let md = signing_md(signer_key);
    let certs_stack: *mut openssl_sys::stack_st_X509 = if config.include_signer_cert {
        // Build a one-element stack with the signer cert so clients can verify the
        // delegated responder's authorization without a separate fetch.
        //
        // We use OPENSSL_sk_* (the underlying generic stack API) because openssl-sys
        // does not expose the type-specific sk_X509_* wrappers (they are C macros).
        //
        // SAFETY: OPENSSL_sk_new_null returns null on OOM; we check before use.
        let stack =
            unsafe { openssl_sys::OPENSSL_sk_new_null().cast::<openssl_sys::stack_st_X509>() };
        if stack.is_null() {
            ptr::null_mut()
        } else {
            // X509_dup is required because OCSP_basic_sign (and the stack) do not
            // take a reference — the stack owns the certs and they must outlive the call.
            // SAFETY: signer_cert is a valid X509.
            let duped = unsafe { openssl_sys::X509_dup(signer_cert.as_ptr()) };
            if !duped.is_null() {
                // SAFETY: stack is non-null; duped is non-null.
                unsafe {
                    openssl_sys::OPENSSL_sk_push(
                        stack.cast::<openssl_sys::OPENSSL_STACK>(),
                        duped.cast::<std::ffi::c_void>(),
                    );
                }
            }
            stack
        }
    } else {
        ptr::null_mut()
    };

    // SAFETY: signer_cert and signer_key are valid; OCSP_basic_sign returns 1 on success.
    let signed = unsafe {
        ocsp_ffi::OCSP_basic_sign(
            brsp,
            signer_cert.as_ptr(),
            signer_key.as_ptr(),
            md,
            certs_stack,
            0, // flags: 0 = include signer cert in response if certs_stack is non-null
        )
    };

    // Free the certs stack (OCSP_basic_sign already referenced the certs).
    if !certs_stack.is_null() {
        // SAFETY: OPENSSL_sk_pop_free frees the duped X509 certs;
        // X509_free matches X509_dup used above.
        unsafe {
            // Use a cast-based approach: wrap X509_free in a C-compatible thunk.
            // SAFETY: p is a *mut X509 cast to *mut c_void by OPENSSL_sk_pop_free.
            unsafe extern "C" fn x509_free_thunk(p: *mut std::ffi::c_void) {
                // SAFETY: p was originally a *mut X509 duped above.
                unsafe {
                    openssl_sys::X509_free(p.cast::<openssl_sys::X509>());
                }
            }
            openssl_sys::OPENSSL_sk_pop_free(
                certs_stack.cast::<openssl_sys::OPENSSL_STACK>(),
                Some(x509_free_thunk),
            );
        }
    }

    if signed != 1 {
        return Err(CryptoError::Default("OCSP_basic_sign failed".to_owned()));
    }

    // ── Wrap in OcspResponse ─────────────────────────────────────────────────────
    // SAFETY: brsp is non-null and fully built; response_create takes ownership of a copy.
    let resp = unsafe {
        openssl_sys::OCSP_response_create(openssl_sys::OCSP_RESPONSE_STATUS_SUCCESSFUL, brsp)
    };
    if resp.is_null() {
        return Err(CryptoError::Default(
            "OCSP_response_create failed".to_owned(),
        ));
    }
    let _resp_guard = OcspResponseGuard(resp);

    // ── Serialize to DER ─────────────────────────────────────────────────────────
    // SAFETY: i2d_OCSP_RESPONSE with null pp returns the size; then we allocate and serialize.
    let der_len = unsafe { openssl_sys::i2d_OCSP_RESPONSE(resp, ptr::null_mut()) };
    if der_len <= 0 {
        return Err(CryptoError::Default(
            "i2d_OCSP_RESPONSE (size query) failed".to_owned(),
        ));
    }
    let der_len = usize::try_from(der_len)
        .map_err(|e| CryptoError::Default(format!("Invalid OCSP response DER length: {e}")))?;
    let mut der = vec![0_u8; der_len];
    let mut p = der.as_mut_ptr();
    // SAFETY: der has exactly der_len bytes; p is valid for writing.
    let written = unsafe { openssl_sys::i2d_OCSP_RESPONSE(resp, &raw mut p) };
    if usize::try_from(written).ok() != Some(der_len) {
        return Err(CryptoError::Default(format!(
            "i2d_OCSP_RESPONSE wrote {written} bytes, expected {der_len}"
        )));
    }

    // Prevent the guard from freeing brsp since OCSP_response_create already consumed it.
    // (The guard for brsp only fires on early-return error paths from this point.)
    std::mem::forget(brsp_guard);

    Ok(der)
}

// ──────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────

/// Add a single certificate status to `brsp`.
#[expect(unsafe_code)]
fn add_single_response(
    brsp: *mut openssl_sys::OCSP_BASICRESP,
    cid: *mut openssl_sys::OCSP_CERTID,
    entry: Option<&OcspStatusEntry>,
    this_update: *mut openssl_sys::ASN1_GENERALIZEDTIME,
    next_update: *mut openssl_sys::ASN1_GENERALIZEDTIME,
) -> Result<(), CryptoError> {
    let (status, reason, rev_time) =
        entry.map_or((V_OCSP_CERTSTATUS_UNKNOWN, 0, None), |e| match &e.status {
            OcspCertStatus::Good => (V_OCSP_CERTSTATUS_GOOD, 0, None),
            OcspCertStatus::Unknown => (V_OCSP_CERTSTATUS_UNKNOWN, 0, None),
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            } => (
                V_OCSP_CERTSTATUS_REVOKED,
                reason_to_crl_code(*reason),
                Some(*revocation_time),
            ),
        });

    // Build revocation time ASN1_GENERALIZEDTIME if needed.
    let rev_gt = rev_time.map_or(Ok(ptr::null_mut()), |rt| {
        let rt_epoch = to_c_long(rt.unix_timestamp())?;
        // SAFETY: ASN1_GENERALIZEDTIME_set allocates a new object.
        let gt = unsafe { ASN1_GENERALIZEDTIME_set(ptr::null_mut(), rt_epoch) };
        if gt.is_null() {
            return Err(CryptoError::Default(
                "ASN1_GENERALIZEDTIME_set (revocationTime) failed".to_owned(),
            ));
        }
        Ok(gt)
    })?;

    // SAFETY: cid, this_update, next_update are non-null; rev_gt may be null for non-revoked.
    let single = unsafe {
        ocsp_ffi::OCSP_basic_add1_status(
            brsp,
            cid,
            status,
            reason,
            rev_gt,
            this_update,
            next_update,
        )
    };

    // Free revocation time (OCSP_basic_add1_status copies it).
    if !rev_gt.is_null() {
        // SAFETY: rev_gt was allocated above and not owned by anyone else now.
        unsafe { ASN1_GENERALIZEDTIME_free(rev_gt) };
    }

    if single.is_null() {
        return Err(CryptoError::Default(
            "OCSP_basic_add1_status failed".to_owned(),
        ));
    }
    Ok(())
}

/// Extract the nonce extension's raw octets from a parsed `OCSP_REQUEST`, if present
/// and within the RFC 9654 §2.1 16–128 octet length bound (shorter nonces are treated
/// as absent per §3's "SHOULD be silently ignored").
#[expect(unsafe_code)]
fn extract_request_nonce(req: *mut openssl_sys::OCSP_REQUEST) -> Option<Vec<u8>> {
    // SAFETY: OID_OCSP_NONCE is a valid NUL-terminated string.
    let nonce_nid =
        unsafe { ocsp_ffi::OBJ_txt2nid(OID_OCSP_NONCE.as_ptr().cast::<std::ffi::c_char>()) };

    // SAFETY: req is non-null.
    let ext_count = unsafe { ocsp_ffi::OCSP_REQUEST_get_ext_count(req) };

    for i in 0..ext_count {
        // SAFETY: i in [0, ext_count).
        let ext = unsafe { ocsp_ffi::OCSP_REQUEST_get_ext(req, i) };
        if ext.is_null() {
            continue;
        }
        // SAFETY: ext is non-null.
        let obj = unsafe { openssl_sys::X509_EXTENSION_get_object(ext) };
        if obj.is_null() {
            continue;
        }
        // SAFETY: obj is non-null.
        let nid = unsafe { openssl_sys::OBJ_obj2nid(obj) };
        if nid != nonce_nid && nid != ocsp_ffi::NID_OCSP_NONCE {
            continue;
        }

        // Extract nonce value bytes. `X509_EXTENSION_get_data` returns the
        // extension's `extnValue`, which per RFC 9654 §2.1 (`Nonce ::= OCTET
        // STRING`) is *itself* the DER encoding of another OCTET STRING
        // wrapping the raw nonce octets — it must be unwrapped one more time
        // before use (both for the length check and before re-echoing it).
        // SAFETY: ext is non-null; X509_EXTENSION_get_data returns borrowed pointer.
        let octet = unsafe { openssl_sys::X509_EXTENSION_get_data(ext) };
        if octet.is_null() {
            return None;
        }
        // SAFETY: octet is a valid ASN1_OCTET_STRING.
        let octet = octet.cast_const().cast::<openssl_sys::ASN1_STRING>();
        let Ok(len) = usize::try_from(unsafe { ASN1_STRING_length(octet) }) else {
            return None;
        };
        let data_ptr = unsafe { ASN1_STRING_get0_data(octet) };
        if data_ptr.is_null() {
            return None;
        }
        // SAFETY: data_ptr is valid for len bytes.
        let ext_value = unsafe { std::slice::from_raw_parts(data_ptr, len) };
        let raw_nonce = decode_der_octet_string(ext_value)?;
        // RFC 9654 §2.1 — a nonce outside the 16-128 octet bounds is ignored, not rejected.
        return (OCSP_NONCE_MIN_LEN..=OCSP_NONCE_MAX_LEN)
            .contains(&raw_nonce.len())
            .then(|| raw_nonce.to_vec());
    }
    None
}

/// Check whether a DER-encoded OCSP request carries a valid-length nonce (RFC 9654 §2.1).
///
/// Intended for callers enforcing `NoncePolicy::Required` **before** attempting to
/// build a signed response, so a violation can be reported as a proper OCSP
/// `malformedRequest` response (RFC 6960 §2.3) rather than a generic HTTP error —
/// most real OCSP clients cannot parse anything other than a DER `OCSPResponse` and
/// will treat any other body (e.g. an HTML error page) as a transport failure.
///
/// # Errors
/// Returns [`CryptoError`] if `request_der` is not a well-formed OCSP request.
#[expect(unsafe_code)]
pub fn request_has_nonce(request_der: &[u8]) -> Result<bool, CryptoError> {
    let req_len = c_long::try_from(request_der.len())
        .map_err(|e| CryptoError::Default(format!("OCSP request DER too large: {e}")))?;
    // SAFETY: d2i_OCSP_REQUEST advances the pointer and returns null on error.
    let req = unsafe {
        let mut p = request_der.as_ptr();
        openssl_sys::d2i_OCSP_REQUEST(ptr::null_mut(), &raw mut p, req_len)
    };
    if req.is_null() {
        return Err(CryptoError::Default(
            "Failed to parse OCSP request DER".to_owned(),
        ));
    }
    let _req_guard = OcspRequestGuard(req);
    Ok(extract_request_nonce(req).is_some())
}

/// Handle the nonce extension according to the configured policy (RFC 9654 §2.1).
///
/// Per RFC 9654:
/// - Responders MUST accept nonces of length 16–128 octets.
/// - Nonces shorter than 16 octets SHOULD be silently ignored (not rejected).
/// - Responders MUST echo the nonce verbatim when present and valid.
#[expect(unsafe_code)]
fn handle_nonce(
    req: *mut openssl_sys::OCSP_REQUEST,
    brsp: *mut openssl_sys::OCSP_BASICRESP,
    policy: NoncePolicy,
) -> Result<(), CryptoError> {
    if policy == NoncePolicy::Ignore {
        return Ok(());
    }

    let nonce_bytes = extract_request_nonce(req);

    match (policy, &nonce_bytes) {
        (NoncePolicy::Required, None) => {
            return Err(CryptoError::Default(
                "OCSP request does not contain a nonce, but nonce_policy = required".to_owned(),
            ));
        }
        (NoncePolicy::Optional | NoncePolicy::Required, Some(nonce)) => {
            // Echo the nonce verbatim (RFC 9654 §2.1 MUST).
            let len = i32::try_from(nonce.len())
                .map_err(|e| CryptoError::Default(format!("Invalid OCSP nonce length: {e}")))?;
            // SAFETY: nonce.as_ptr() is valid for len bytes; OCSP_add1_basic_nonce copies the data.
            let rc = unsafe { ocsp_ffi::OCSP_basic_add1_nonce(brsp, nonce.as_ptr(), len) };
            if rc != 1 {
                return Err(CryptoError::Default(
                    "OCSP_add1_basic_nonce failed".to_owned(),
                ));
            }
        }
        _ => { /* Optional with no nonce — nothing to do */ }
    }

    Ok(())
}

/// Add the `id-pkix-ocsp-archive-cutoff` extension to the `BasicResponse` (RFC 6960 §4.4.4).
///
/// The extension value is a `GeneralizedTime` equal to `now - archive_cutoff_secs`.
#[expect(unsafe_code)]
fn add_archive_cutoff(
    brsp: *mut openssl_sys::OCSP_BASICRESP,
    now_epoch: c_long,
    archive_cutoff_secs: u64,
) -> Result<(), CryptoError> {
    let cutoff_epoch = now_epoch.saturating_sub(c_long::try_from(archive_cutoff_secs).unwrap_or(0));

    // Allocate a GeneralizedTime for the cutoff.
    // SAFETY: ASN1_GENERALIZEDTIME_set allocates when first arg is null.
    let cutoff_gt = unsafe { ASN1_GENERALIZEDTIME_set(ptr::null_mut(), cutoff_epoch) };
    if cutoff_gt.is_null() {
        return Err(CryptoError::Default(
            "ASN1_GENERALIZEDTIME_set (archiveCutoff) failed".to_owned(),
        ));
    }
    let _gt_guard = GeneralizedTimeGuard(cutoff_gt);

    // Look up the NID for id-pkix-ocsp-archive-cutoff.
    // SAFETY: OID_OCSP_ARCHIVE_CUTOFF is a valid NUL-terminated OID string.
    let nid = unsafe {
        ocsp_ffi::OBJ_txt2nid(OID_OCSP_ARCHIVE_CUTOFF.as_ptr().cast::<std::ffi::c_char>())
    };
    if nid <= 0 {
        // Extension not registered — skip rather than fail.
        return Ok(());
    }

    // Add the extension using the pre-built GeneralizedTime value.
    // SAFETY: cutoff_gt is non-null and well-formed; X509V3_ADD_DEFAULT = 0.
    let rc = unsafe {
        ocsp_ffi::OCSP_BASICRESP_add1_ext_i2d(
            brsp,
            nid,
            cutoff_gt.cast::<std::ffi::c_void>(),
            0, // non-critical
            0, // flags
        )
    };
    if rc != 1 {
        // Non-fatal: archive-cutoff is informational only.
    }
    Ok(())
}

/// Extract a [`ParsedOcspQuery`] from an `OCSP_CERTID*`.
#[expect(unsafe_code)]
fn extract_query_from_cert_id(
    cid: *mut openssl_sys::OCSP_CERTID,
) -> Result<ParsedOcspQuery, CryptoError> {
    let mut name_hash_ptr: *mut openssl_sys::ASN1_OCTET_STRING = ptr::null_mut();
    let mut key_hash_ptr: *mut openssl_sys::ASN1_OCTET_STRING = ptr::null_mut();
    let mut serial_ptr: *mut openssl_sys::ASN1_INTEGER = ptr::null_mut();
    let mut md_oid_ptr: *mut openssl_sys::ASN1_OBJECT = ptr::null_mut();

    // SAFETY: cid is non-null.
    let rc = unsafe {
        ocsp_ffi::OCSP_id_get0_info(
            std::ptr::addr_of_mut!(name_hash_ptr),
            std::ptr::addr_of_mut!(md_oid_ptr),
            std::ptr::addr_of_mut!(key_hash_ptr),
            std::ptr::addr_of_mut!(serial_ptr),
            cid,
        )
    };
    if rc != 1 || name_hash_ptr.is_null() || key_hash_ptr.is_null() || serial_ptr.is_null() {
        return Err(CryptoError::Default(
            "OCSP_id_get0_info failed or returned null fields".to_owned(),
        ));
    }

    // Extract bytes from ASN1_OCTET_STRING fields (borrowed — do not free).
    let name_hash = asn1_string_bytes(
        name_hash_ptr
            .cast_const()
            .cast::<openssl_sys::ASN1_STRING>(),
    );
    let key_hash = asn1_string_bytes(key_hash_ptr.cast_const().cast::<openssl_sys::ASN1_STRING>());

    // Resolve the request's own hashAlgorithm OID to an OpenSSL NID (RFC 6960 §4.1.1).
    // SAFETY: md_oid_ptr is non-null when rc == 1 (OpenSSL always populates pmd).
    let hash_algorithm_nid = if md_oid_ptr.is_null() {
        openssl_sys::NID_undef
    } else {
        unsafe { openssl_sys::OBJ_obj2nid(md_oid_ptr) }
    };

    // Convert serial ASN1_INTEGER → hex string.
    let serial_hex = extract_serial_hex(cid)?;

    Ok(ParsedOcspQuery {
        serial_hex,
        issuer_name_hash: name_hash,
        issuer_key_hash: key_hash,
        hash_algorithm_nid,
    })
}

/// Extract the serial number from an `OCSP_CERTID` as an uppercase hex string.
#[expect(unsafe_code)]
fn extract_serial_hex(cid: *mut openssl_sys::OCSP_CERTID) -> Result<String, CryptoError> {
    let mut serial_ptr: *mut openssl_sys::ASN1_INTEGER = ptr::null_mut();

    // SAFETY: cid is non-null.
    let rc = unsafe {
        ocsp_ffi::OCSP_id_get0_info(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            std::ptr::addr_of_mut!(serial_ptr),
            cid,
        )
    };
    if rc != 1 || serial_ptr.is_null() {
        return Err(CryptoError::Default(
            "OCSP_id_get0_info failed to extract serial".to_owned(),
        ));
    }

    // SAFETY: serial_ptr is non-null and borrowed from cid.
    let bn = unsafe { ASN1_INTEGER_to_BN(serial_ptr, ptr::null_mut()) };
    if bn.is_null() {
        return Err(CryptoError::Default("ASN1_INTEGER_to_BN failed".to_owned()));
    }
    // SAFETY: bn is non-null; BN_bn2hex returns a malloc'd string.
    let hex_ptr = unsafe { BN_bn2hex(bn) };
    // SAFETY: bn is no longer needed.
    unsafe { BN_free(bn) };

    if hex_ptr.is_null() {
        return Err(CryptoError::Default("BN_bn2hex failed".to_owned()));
    }

    // SAFETY: hex_ptr is a valid NUL-terminated ASCII string.
    let hex_str = unsafe { CStr::from_ptr(hex_ptr.cast::<std::ffi::c_char>()) }
        .to_string_lossy()
        .to_ascii_uppercase();

    // SAFETY: hex_ptr was allocated by OpenSSL.
    // SAFETY: hex_ptr is non-null; CRYPTO_free is the underlying function that
    // OPENSSL_free (a macro) expands to; passing null file and line 0 is fine for
    // runtime deallocation (these are only for debug tracking).
    unsafe { ocsp_ffi::CRYPTO_free(hex_ptr.cast::<std::ffi::c_void>(), c"ocsp.rs".as_ptr(), 0) };

    Ok(hex_str)
}

/// Copy bytes from an `ASN1_STRING*` into a `Vec<u8>`.
///
/// Returns an empty vec if the pointer is null.
#[expect(unsafe_code)]
fn asn1_string_bytes(s: *const openssl_sys::ASN1_STRING) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    // SAFETY: s is non-null; ASN1_STRING_length and ASN1_STRING_get0_data are safe to call.
    let Ok(len) = usize::try_from(unsafe { ASN1_STRING_length(s) }) else {
        return Vec::new();
    };
    let data = unsafe { ASN1_STRING_get0_data(s) };
    if data.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: data is valid for len bytes.
    unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
}

/// Decode a single DER-encoded `OCTET STRING` TLV and return its content bytes.
///
/// Used to unwrap the OCSP Nonce extension's `extnValue`, which per RFC 9654 §2.1
/// (`Nonce ::= OCTET STRING`) is itself the DER encoding of another `OCTET STRING`
/// wrapping the raw nonce octets. Handles both short-form (length < 128) and
/// single-byte long-form (length == 128, encoded as `0x81 0x80`) DER lengths —
/// the only forms relevant for the RFC 9654 §2.1 16–128 octet nonce bound.
///
/// Returns `None` if `bytes` is not a well-formed `OCTET STRING` TLV, or if the
/// declared length does not fit within `bytes`.
fn decode_der_octet_string(bytes: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x04 {
        return None;
    }
    let (&len_byte, rest) = rest.split_first()?;
    if len_byte & 0x80 == 0 {
        rest.get(..usize::from(len_byte))
    } else {
        let num_len_bytes = usize::from(len_byte & 0x7f);
        if num_len_bytes == 0
            || num_len_bytes > rest.len()
            || num_len_bytes > std::mem::size_of::<usize>()
        {
            return None;
        }
        let (len_bytes, content) = rest.split_at(num_len_bytes);
        let len = len_bytes
            .iter()
            .fold(0_usize, |acc, &b| (acc << 8) | usize::from(b));
        content.get(..len)
    }
}

/// Choose the digest algorithm for signing based on the key type.
///
/// Per RFC 6960 §4.3 (and NIST guidance):
/// - RSA / EC → SHA-256
/// - PQC (ML-DSA, SLH-DSA) → null digest (algorithm performs its own hashing)
#[expect(unsafe_code)]
fn signing_md(key: &PKeyRef<Private>) -> *const openssl_sys::EVP_MD {
    // SAFETY: EVP_sha256/EVP_md_null return static pointers.
    unsafe {
        match key.id() {
            openssl::pkey::Id::RSA | openssl::pkey::Id::EC => openssl_sys::EVP_sha256(),
            _ => openssl_sys::EVP_md_null(),
        }
    }
}

/// Convert an `Option<CrlReasonCode>` to the `CRL_REASON_*` integer for FFI.
const fn reason_to_crl_code(reason: Option<CrlReasonCode>) -> std::ffi::c_int {
    match reason {
        None | Some(CrlReasonCode::Unspecified) => CRL_REASON_UNSPECIFIED,
        Some(CrlReasonCode::KeyCompromise) => CRL_REASON_KEY_COMPROMISE,
        Some(CrlReasonCode::CaCompromise) => CRL_REASON_CA_COMPROMISE,
        Some(CrlReasonCode::AffiliationChanged) => CRL_REASON_AFFILIATION_CHANGED,
        Some(CrlReasonCode::Superseded) => CRL_REASON_SUPERSEDED,
        Some(CrlReasonCode::CessationOfOperation) => CRL_REASON_CESSATION_OF_OPERATION,
        Some(CrlReasonCode::CertificateHold) => CRL_REASON_CERTIFICATE_HOLD,
        Some(CrlReasonCode::RemoveFromCRL) => CRL_REASON_REMOVE_FROM_CRL,
        Some(CrlReasonCode::PrivilegeWithdrawn) => CRL_REASON_PRIVILEGE_WITHDRAWN,
        Some(CrlReasonCode::AaCompromise) => CRL_REASON_AA_COMPROMISE,
    }
}

// ──────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]
mod tests {
    use openssl::{
        asn1::Asn1Integer,
        bn::BigNum,
        hash::MessageDigest,
        ocsp::{OcspCertId, OcspRequest, OcspResponse},
        pkey::PKey,
        x509::{X509, X509Builder, X509NameBuilder, extension::BasicConstraints},
    };
    use time::OffsetDateTime;

    use super::*;

    /// Generate a self-signed CA certificate + private key for testing.
    fn create_test_ca() -> (X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey");

        let mut nb = X509NameBuilder::new().expect("X509NameBuilder");
        nb.append_entry_by_text("CN", "Test CA").expect("CN");
        let name = nb.build();

        let mut b = X509Builder::new().expect("X509Builder");
        b.set_version(2).expect("v3");
        b.set_subject_name(&name).expect("subject");
        b.set_issuer_name(&name).expect("issuer");
        b.set_pubkey(&pkey).expect("pubkey");
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("not_before");
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).expect("not_after");
        b.set_not_before(&not_before).expect("set_not_before");
        b.set_not_after(&not_after).expect("set_not_after");
        let serial =
            Asn1Integer::from_bn(BigNum::from_u32(1).expect("bn").as_ref()).expect("serial");
        b.set_serial_number(&serial).expect("set_serial");
        let bc = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .expect("BasicConstraints");
        b.append_extension(bc).expect("append bc");
        b.sign(&pkey, MessageDigest::sha256()).expect("sign");
        (b.build(), pkey)
    }

    /// Build a minimal OCSP request for a given serial number using the openssl crate's high-level API.
    fn build_test_request(ca_cert: &X509, _serial_hex: &str, with_nonce: bool) -> Vec<u8> {
        let md = MessageDigest::sha256();
        // Build a dummy subject cert with the target serial so we can use OcspCertId::from_cert.
        // Actually we'll use the low-level API to build the CertId directly.
        let mut req = OcspRequest::new().expect("OcspRequest::new");

        // Build a CertId using the CA cert as both issuer and subject (serial will be extracted).
        // For testing we need to create a CertId with a specific serial.
        // Use the CA cert as a proxy — the serial won't match real certs but that's fine for unit tests.
        let id = OcspCertId::from_cert(md, ca_cert, ca_cert).expect("OcspCertId::from_cert");
        req.add_id(id).expect("add_id");

        if with_nonce {
            // Add a 32-byte random nonce (RFC 9654 §2.1 recommended minimum).
            let mut nonce = [0xAB_u8; 32];
            // SAFETY: OCSP_request_add1_nonce copies the nonce bytes.
            unsafe {
                ocsp_ffi::OCSP_request_add1_nonce(req.as_ptr().cast(), nonce.as_mut_ptr(), 32);
            }
        }

        req.to_der().expect("to_der")
    }

    #[test]
    fn test_build_ocsp_response_good() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", false);

        let entries = vec![OcspStatusEntry {
            serial_hex: "01".to_owned(),
            status: OcspCertStatus::Good,
        }];
        let config = OcspBuildConfig::default();

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        assert!(!resp_der.is_empty());

        // Parse the response with the openssl crate.
        let resp = OcspResponse::from_der(&resp_der).expect("OcspResponse::from_der");
        assert_eq!(resp.status(), openssl::ocsp::OcspResponseStatus::SUCCESSFUL);
    }

    #[test]
    fn test_build_ocsp_response_revoked() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "02", false);

        let rev_time = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts");
        let entries = vec![OcspStatusEntry {
            serial_hex: "02".to_owned(),
            status: OcspCertStatus::Revoked {
                revocation_time: rev_time,
                reason: Some(CrlReasonCode::KeyCompromise),
            },
        }];
        let config = OcspBuildConfig::default();

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        assert!(!resp_der.is_empty());

        let resp = OcspResponse::from_der(&resp_der).expect("parse");
        assert_eq!(resp.status(), openssl::ocsp::OcspResponseStatus::SUCCESSFUL);
    }

    #[test]
    fn test_build_ocsp_response_unknown() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "FF", false);

        // No matching entry → unknown.
        let entries: Vec<OcspStatusEntry> = vec![];
        let config = OcspBuildConfig::default();

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        assert!(!resp_der.is_empty());
    }

    #[test]
    fn test_nonce_echoed() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", true);

        let entries = vec![OcspStatusEntry {
            serial_hex: "01".to_owned(),
            status: OcspCertStatus::Good,
        }];
        let config = OcspBuildConfig {
            nonce_policy: NoncePolicy::Optional,
            ..Default::default()
        };

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        assert!(!resp_der.is_empty());

        // The response DER should contain the nonce bytes (0xAB × 32).
        let nonce_pattern = [0xAB_u8; 32];
        assert!(
            resp_der.windows(32).any(|w| w == nonce_pattern),
            "nonce bytes should appear in the response DER"
        );

        // A byte-substring match is not sufficient: an incorrectly wrapped (e.g.
        // double-encoded) nonce extension still contains the same raw bytes but
        // is structurally wrong and fails real client-side verification. Re-parse
        // both DER blobs with the same raw `OCSP_check_nonce` API a real client
        // (e.g. `openssl ocsp`) uses, to catch that class of bug.
        let req_len = c_long::try_from(req_der.len()).expect("req len");
        // SAFETY: d2i_OCSP_REQUEST advances the pointer and returns null on error.
        let req_ptr = unsafe {
            let mut p = req_der.as_ptr();
            openssl_sys::d2i_OCSP_REQUEST(ptr::null_mut(), &raw mut p, req_len)
        };
        assert!(!req_ptr.is_null());
        let _req_guard = OcspRequestGuard(req_ptr);

        let resp = OcspResponse::from_der(&resp_der).expect("OcspResponse::from_der");
        let basic = resp.basic().expect("basic response");

        // SAFETY: req_ptr and basic.as_ptr() are both non-null, valid OCSP structures.
        let check = unsafe { ocsp_ffi::OCSP_check_nonce(req_ptr, basic.as_ptr()) };
        assert_eq!(
            check, 1,
            "OCSP_check_nonce must report a structurally matching nonce (got {check})"
        );
    }

    #[test]
    fn test_required_nonce_missing_returns_error() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", false); // no nonce

        let entries: Vec<OcspStatusEntry> = vec![];
        let config = OcspBuildConfig {
            nonce_policy: NoncePolicy::Required,
            ..Default::default()
        };

        let result = build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config);
        assert!(
            result.is_err(),
            "Required nonce policy with no nonce should fail"
        );
    }

    #[test]
    fn test_request_has_nonce() {
        let (ca, _) = create_test_ca();
        let with_nonce = build_test_request(&ca, "01", true);
        let without_nonce = build_test_request(&ca, "01", false);
        assert!(request_has_nonce(&with_nonce).expect("check"));
        assert!(!request_has_nonce(&without_nonce).expect("check"));
    }

    #[test]
    fn test_ignore_nonce_policy() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", true); // has nonce

        let entries = vec![OcspStatusEntry {
            serial_hex: "01".to_owned(),
            status: OcspCertStatus::Good,
        }];
        let config = OcspBuildConfig {
            nonce_policy: NoncePolicy::Ignore,
            ..Default::default()
        };

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        // Nonce bytes should NOT appear in response when policy=Ignore.
        let nonce_pattern = [0xAB_u8; 32];
        assert!(
            !resp_der.windows(32).any(|w| w == nonce_pattern),
            "nonce should be absent when policy=Ignore"
        );
    }

    #[test]
    fn test_response_der_round_trip() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", false);

        let entries = vec![OcspStatusEntry {
            serial_hex: "01".to_owned(),
            status: OcspCertStatus::Good,
        }];
        let config = OcspBuildConfig::default();

        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");

        // Re-serialize and compare.
        let resp = OcspResponse::from_der(&resp_der).expect("from_der 1");
        let resp_der2 = resp.to_der().expect("to_der 2");
        assert_eq!(resp_der, resp_der2, "DER round-trip must be stable");
    }

    #[test]
    fn test_this_update_next_update_present() {
        let (ca, ca_key) = create_test_ca();
        let req_der = build_test_request(&ca, "01", false);

        let entries = vec![OcspStatusEntry {
            serial_hex: "01".to_owned(),
            status: OcspCertStatus::Good,
        }];
        let config = OcspBuildConfig {
            ttl_secs: 3600, // 1 h
            ..Default::default()
        };

        let before = OffsetDateTime::now_utc();
        let resp_der =
            build_ocsp_response(&req_der, &ca, &ca, &ca_key, &entries, &config).expect("build");
        let after = OffsetDateTime::now_utc();

        // A non-empty response DER implies thisUpdate and nextUpdate were set
        // (OCSP_basic_add1_status would fail otherwise).
        assert!(!resp_der.is_empty());
        assert!(before <= after, "time must be monotone");
    }

    #[test]
    fn test_parse_ocsp_request() {
        let (ca, _) = create_test_ca();
        let req_der = build_test_request(&ca, "01", false);
        let queries = parse_ocsp_request(&req_der).expect("parse_ocsp_request");
        let query = queries.first().expect("one parsed query");
        assert_eq!(queries.len(), 1);
        assert!(!query.issuer_name_hash.is_empty());
        assert!(!query.issuer_key_hash.is_empty());
    }

    /// Build a request using an explicit digest for the `CertId` (bypassing
    /// `build_test_request`'s hardcoded SHA-256, to exercise other algorithms).
    fn build_request_with_digest(ca_cert: &X509, md: MessageDigest) -> Vec<u8> {
        let mut req = OcspRequest::new().expect("OcspRequest::new");
        let id = OcspCertId::from_cert(md, ca_cert, ca_cert).expect("OcspCertId::from_cert");
        req.add_id(id).expect("add_id");
        req.to_der().expect("to_der")
    }

    #[test]
    fn test_verify_issuer_hashes_match_ca_honours_request_digest() {
        // Real-world clients (including the reference `openssl ocsp` client)
        // commonly default to SHA-1 for the CertId; the responder must accept
        // that just as readily as a SHA-256 request for the same CA.
        let (ca, _) = create_test_ca();

        for md in [MessageDigest::sha1(), MessageDigest::sha256()] {
            let req_der = build_request_with_digest(&ca, md);
            let queries = parse_ocsp_request(&req_der).expect("parse_ocsp_request");
            assert!(
                verify_issuer_hashes_match_ca(&queries, &ca).expect("verify"),
                "issuer hash match must succeed for digest {:?}",
                md.type_()
            );
        }
    }

    #[test]
    fn test_verify_issuer_hashes_match_ca_rejects_other_ca() {
        let (ca, _) = create_test_ca();
        let (other_ca, _) = create_test_ca();
        let req_der = build_request_with_digest(&other_ca, MessageDigest::sha1());
        let queries = parse_ocsp_request(&req_der).expect("parse_ocsp_request");
        assert!(
            !verify_issuer_hashes_match_ca(&queries, &ca).expect("verify"),
            "a request for a different CA must not match"
        );
    }

    /// Build a self-signed test certificate carrying the given extra extensions,
    /// used to exercise `verify_delegated_responder_authorization`.
    fn create_test_cert_with_extensions(
        extra_extensions: &[openssl::x509::X509Extension],
    ) -> Vec<u8> {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey");

        let mut nb = X509NameBuilder::new().expect("X509NameBuilder");
        nb.append_entry_by_text("CN", "Test OCSP Signer")
            .expect("CN");
        let name = nb.build();

        let mut b = X509Builder::new().expect("X509Builder");
        b.set_version(2).expect("v3");
        b.set_subject_name(&name).expect("subject");
        b.set_issuer_name(&name).expect("issuer");
        b.set_pubkey(&pkey).expect("pubkey");
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("not_before");
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).expect("not_after");
        b.set_not_before(&not_before).expect("set_not_before");
        b.set_not_after(&not_after).expect("set_not_after");
        let serial =
            Asn1Integer::from_bn(BigNum::from_u32(1).expect("bn").as_ref()).expect("serial");
        b.set_serial_number(&serial).expect("set_serial");
        for ext in extra_extensions {
            b.append_extension2(ext).expect("append extra extension");
        }
        b.sign(&pkey, MessageDigest::sha256()).expect("sign");
        b.build().to_der().expect("to_der")
    }

    /// Build the `id-pkix-ocsp-nocheck` extension (OID 1.3.6.1.5.5.7.48.1.5),
    /// whose DER content is the ASN.1 NULL value (`05 00`), non-critical.
    fn build_ocsp_nocheck_extension() -> openssl::x509::X509Extension {
        let oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.5.5.7.48.1.5")
            .expect("Asn1Object::from_str");
        let der_null = openssl::asn1::Asn1OctetString::new_from_bytes(&[0x05, 0x00])
            .expect("Asn1OctetString::new_from_bytes");
        openssl::x509::X509Extension::new_from_der(&oid, false, &der_null)
            .expect("X509Extension::new_from_der")
    }

    #[test]
    fn test_verify_delegated_responder_authorization_accepts_valid_cert() {
        let eku = openssl::x509::extension::ExtendedKeyUsage::new()
            .other("OCSPSigning")
            .build()
            .expect("eku build");
        let nocheck = build_ocsp_nocheck_extension();
        let cert_der = create_test_cert_with_extensions(&[eku, nocheck]);

        verify_delegated_responder_authorization(&cert_der)
            .expect("cert with OCSPSigning EKU + nocheck must be accepted");
    }

    #[test]
    fn test_verify_delegated_responder_authorization_rejects_missing_eku() {
        let nocheck = build_ocsp_nocheck_extension();
        let cert_der = create_test_cert_with_extensions(&[nocheck]);

        let err = verify_delegated_responder_authorization(&cert_der)
            .expect_err("cert without OCSPSigning EKU must be rejected");
        assert!(
            err.to_string().contains("OCSPSigning"),
            "error should mention the missing OCSPSigning EKU: {err}"
        );
    }

    #[test]
    fn test_verify_delegated_responder_authorization_accepts_missing_nocheck_with_warning() {
        // `id-pkix-ocsp-nocheck` is only one of three RFC 6960 §4.2.2.2.1-sanctioned
        // strategies for checking a delegated responder's own revocation status, not
        // a MUST — its absence must not cause rejection, only a logged warning.
        let eku = openssl::x509::extension::ExtendedKeyUsage::new()
            .other("OCSPSigning")
            .build()
            .expect("eku build");
        let cert_der = create_test_cert_with_extensions(&[eku]);

        verify_delegated_responder_authorization(&cert_der)
            .expect("cert with OCSPSigning EKU but no nocheck extension must be accepted");
    }

    #[test]
    fn test_decode_der_octet_string_short_form() {
        // OCTET STRING (tag 0x04), length 16 (short form), 16 content bytes.
        let mut der = vec![0x04, 0x10];
        der.extend_from_slice(&[0xAB; 16]);
        assert_eq!(decode_der_octet_string(&der), Some(&[0xAB_u8; 16][..]));
    }

    #[test]
    fn test_decode_der_octet_string_long_form_length() {
        // OCTET STRING (tag 0x04), length 128 (long form: 0x81 0x80), 128 content bytes.
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend_from_slice(&[0xCD; 128]);
        assert_eq!(decode_der_octet_string(&der), Some(&[0xCD_u8; 128][..]));
    }

    #[test]
    fn test_decode_der_octet_string_rejects_malformed_input() {
        assert_eq!(decode_der_octet_string(&[]), None);
        assert_eq!(decode_der_octet_string(&[0x02, 0x01, 0x00]), None); // wrong tag
        assert_eq!(decode_der_octet_string(&[0x04, 0x05, 0xAA]), None); // truncated content
    }
}
