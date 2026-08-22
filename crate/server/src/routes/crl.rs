use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, get,
    web::{Data, Path, Query},
};
use cosmian_logger::info;
use serde::Deserialize;

use crate::{core::KMS, result::KResult};

// HTTP-date IMF-fixdate lookups (RFC 7231 §7.1.1.1)
const HTTP_DATE_DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HTTP_DATE_MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Query parameters for the CRL generation endpoint.
#[derive(Debug, Deserialize)]
pub(crate) struct CrlQueryParams {
    /// Output format: `der` (default, RFC 2585) or `pem`.
    pub format: Option<String>,
    /// CRL validity in days (default: 7).
    pub validity_days: Option<u32>,
}

/// Generate and sign a fresh CRL for the specified issuer certificate.
///
/// `GET /certificates/{issuer_id}/crl`
///
/// # Why authentication is required
///
/// Generating a CRL uses the **CA private key** to produce a cryptographic signature.
/// Authentication ensures the caller has object-level read access to the CA key.
/// No special role (Crypto Officer or otherwise) is required — any authenticated
/// user with access to the CA certificate may request its CRL.
///
/// CRL _content_ is public information (RFC 5280 §3) — it lists revoked serial numbers
/// and contains no private key material.  Authentication here protects the CA private
/// key from being used as a signing oracle by unauthenticated callers.
///
/// The generated CRL is persisted to the database and immediately served by the
/// public distribution endpoint (`GET /public/certificates/{id}/crl`).
///
/// Returns the signed CRL in DER (default) or PEM format.
#[get("/certificates/{issuer_id}/crl")]
pub(crate) async fn get_crl(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    path: Path<String>,
    query: Query<CrlQueryParams>,
) -> KResult<HttpResponse> {
    let issuer_id = path.into_inner();
    let user = kms.get_user(&req);
    let format = match query.format.as_deref().unwrap_or("der") {
        "der" => "der",
        "pem" => "pem",
        other => {
            return Err(crate::error::KmsError::InvalidRequest(format!(
                "Invalid format '{other}'; supported values are: der, pem"
            )));
        }
    };

    info!(
        user = user.as_str(),
        issuer_id = issuer_id,
        format = format,
        "GET /certificates/{}/crl",
        issuer_id
    );

    let crl = Box::pin(crate::core::operations::generate_crl::generate_crl(
        &kms,
        &issuer_id,
        query.validity_days,
        &user,
    ))
    .await?;

    if format == "pem" {
        let pem = crl.to_pem().map_err(|e| {
            crate::error::KmsError::ServerError(format!("Failed to encode CRL as PEM: {e}"))
        })?;
        Ok(HttpResponse::Ok()
            .content_type("application/x-pem-file")
            .append_header(("Content-Disposition", "inline; filename=\"crl.pem\""))
            .body(pem))
    } else {
        // Default: DER (RFC 2585 §3)
        let der = crl.to_der().map_err(|e| {
            crate::error::KmsError::ServerError(format!("Failed to encode CRL as DER: {e}"))
        })?;
        Ok(HttpResponse::Ok()
            .content_type("application/pkix-crl")
            .append_header(("Content-Disposition", "inline; filename=\"crl.der\""))
            .body(der))
    }
}

/// Serve the pre-computed CRL from the public distribution point (no authentication).
///
/// `GET /public/certificates/{issuer_id}/crl`
///
/// This endpoint is for **CRL Distribution Point (CDP) URIs** embedded in certificates.
/// Any relying party — browser, TLS stack, OCSP client — can fetch it without credentials,
/// as required by RFC 5280 §3.
///
/// The CRL is served from cache (no CA private key access at serve time) and contains
/// **all** revoked certificates issued by this CA regardless of DB ownership (`find_all`).
///
/// **Automatic refresh**: the CRL is regenerated after every certificate revocation
/// and by the background scheduler before expiry.  On server restart the last signed
/// CRL is loaded from the database, so the endpoint is immediately available.
///
/// **HTTP caching**: responses include `Cache-Control: public, max-age=N` (derived from
/// `nextUpdate − 60s`) and `Last-Modified` headers so relying parties can cache the CRL.
#[get("/public/certificates/{issuer_id}/crl")]
pub(crate) async fn get_crl_public(
    kms: Data<Arc<KMS>>,
    path: Path<String>,
) -> KResult<HttpResponse> {
    let issuer_id = path.into_inner();

    info!(
        issuer_id = issuer_id,
        "GET /public/certificates/{}/crl (unauthenticated)", issuer_id
    );

    let Some((crl_der, generated_at, next_update_str)) =
        crate::core::operations::generate_crl::get_cached_crl(&issuer_id, &kms).await
    else {
        return Ok(HttpResponse::NotFound()
            .content_type("text/plain; charset=utf-8")
            .body(format!(
                "No CRL found for issuer '{issuer_id}'. \
                 The CRL is generated automatically when a certificate issued by this CA \
                 is revoked.  If no certificate has been revoked yet, revoke one to \
                 prime the distribution point, or call GET /certificates/{issuer_id}/crl \
                 (authenticated, Crypto Officer role required when configured)."
            )));
    };

    // RFC 7232 / HTTP caching: tell clients when the CRL was generated.
    // We use a simple approach: convert the elapsed Instant back to an
    // approximate SystemTime and format it as an HTTP-date string.
    // The precision is sufficient for cache-control purposes.
    let elapsed = generated_at.elapsed();
    let last_modified = std::time::SystemTime::now()
        .checked_sub(elapsed)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    // Format as HTTP-date IMF-fixdate (RFC 7231 §7.1.1.1): "Thu, 01 Jan 1970 00:00:00 GMT"
    // Must always use GMT and fixed-width day/month/year fields.
    // `number_days_from_sunday()` returns 0–6; `month()` is a Month enum (1-indexed).
    let last_modified_str = {
        use std::time::UNIX_EPOCH;
        let secs = last_modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let dt = time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(0))
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        let weekday_idx = usize::from(dt.weekday().number_days_from_sunday());
        let month_idx = usize::from(u8::from(dt.month())).saturating_sub(1);
        let day_name = HTTP_DATE_DAY_NAMES
            .get(weekday_idx)
            .copied()
            .unwrap_or("Thu");
        let month_name = HTTP_DATE_MONTH_NAMES
            .get(month_idx)
            .copied()
            .unwrap_or("Jan");
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
    };

    // RFC 7234 / HTTP caching: Cache-Control + Expires so relying parties
    // (browsers, TLS stacks, CDNs) can cache the CRL up to its nextUpdate.
    //
    // We apply a 60-second safety buffer so clients always refresh slightly before
    // the CRL actually expires, preventing windows where cached copies are stale.
    // This matches DigiCert's production practice.
    //
    // `max_age_secs` is 0 when the CRL has already expired or nextUpdate is within
    // the buffer — clients will then fetch immediately on the next check.
    let (cache_control, expires_str) = {
        let now = time::OffsetDateTime::now_utc();
        let next_update = time::OffsetDateTime::parse(
            &next_update_str,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap_or(now);
        let secs_until_expiry = (next_update - now).whole_seconds().max(0);
        let max_age = (secs_until_expiry - 60).max(0);
        let expires_dt = now + time::Duration::seconds(max_age);
        let weekday_idx = usize::from(expires_dt.weekday().number_days_from_sunday());
        let month_idx = usize::from(u8::from(expires_dt.month())).saturating_sub(1);
        let day_name = HTTP_DATE_DAY_NAMES
            .get(weekday_idx)
            .copied()
            .unwrap_or("Thu");
        let month_name = HTTP_DATE_MONTH_NAMES
            .get(month_idx)
            .copied()
            .unwrap_or("Jan");
        let expires = format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            day_name,
            expires_dt.day(),
            month_name,
            expires_dt.year(),
            expires_dt.hour(),
            expires_dt.minute(),
            expires_dt.second()
        );
        (format!("public, max-age={max_age}, no-transform"), expires)
    };

    Ok(HttpResponse::Ok()
        .content_type("application/pkix-crl")
        .append_header(("Last-Modified", last_modified_str))
        .append_header(("Cache-Control", cache_control))
        .append_header(("Expires", expires_str))
        .append_header(("Content-Disposition", "inline; filename=\"crl.der\""))
        .body(crl_der))
}
