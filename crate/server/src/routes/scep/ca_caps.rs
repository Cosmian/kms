//! `GetCACaps` (RFC 8894 §3.5.1 / §3.5.2).

use actix_web::HttpResponse;

/// Capabilities advertised by the server, one per line.
///
/// Fixed on purpose: `DES3` and `SHA-1` are never offered (RFC 8894 §2.9 marks them
/// optional/historical and they are not approved by FIPS 140-3 / SP 800-131A).
const CA_CAPABILITIES: &str = "POSTPKIOperation\nSHA-256\nAES\nRenewal";

/// Answer a `GetCACaps` request as `text/plain`.
pub(super) fn get_ca_caps() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(CA_CAPABILITIES)
}
