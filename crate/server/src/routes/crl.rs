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

/// Generate a CRL for the specified issuer certificate.
///
/// `GET /certificates/{issuer_id}/crl`
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

/// Serve a pre-signed CRL from the in-memory cache (no authentication required).
///
/// `GET /public/certificates/{issuer_id}/crl`
///
/// This endpoint is intended for CRL Distribution Point (CDP) URIs embedded in
/// certificates. Any relying party (browser, TLS stack, etc.) must be able to
/// fetch the CRL without credentials, as required by RFC 5280 §3.
///
/// The CRL bytes are populated by the authenticated `GET /certificates/{id}/crl`
/// endpoint and by automatic CRL regeneration triggered on certificate revocation.
/// If the CRL has never been generated since the last server start, this endpoint
/// returns **404** with a message asking the CA owner to call the authenticated
/// endpoint once to prime the cache.
#[get("/public/certificates/{issuer_id}/crl")]
pub(crate) async fn get_crl_public(path: Path<String>) -> KResult<HttpResponse> {
    let issuer_id = path.into_inner();

    info!(
        issuer_id = issuer_id,
        "GET /public/certificates/{}/crl (unauthenticated)", issuer_id
    );

    let Some((crl_der, generated_at)) =
        crate::core::operations::generate_crl::get_cached_crl(&issuer_id).await
    else {
        return Ok(HttpResponse::NotFound()
            .content_type("text/plain; charset=utf-8")
            .body(format!(
                "No CRL found for issuer '{issuer_id}'. \
                 The CA owner must call GET /certificates/{issuer_id}/crl \
                 (authenticated) at least once to prime the cache."
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

    Ok(HttpResponse::Ok()
        .content_type("application/pkix-crl")
        .append_header(("Last-Modified", last_modified_str))
        .append_header(("Content-Disposition", "inline; filename=\"crl.der\""))
        .body(crl_der))
}
