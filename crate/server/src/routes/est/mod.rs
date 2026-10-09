//! EST (Enrollment over Secure Transport, RFC 7030) endpoints.
//!
//! ```text
//! GET  /.well-known/est/cacerts          (RFC 7030 §4.1)
//! GET  /.well-known/est/csrattrs         (RFC 7030 §4.5)
//! POST /.well-known/est/simpleenroll     (RFC 7030 §4.2.1)
//! POST /.well-known/est/simplereenroll   (RFC 7030 §4.2.2)
//! ```
//!
//! All routes answer 404 unless `est_enabled = true`. `cacerts` and `csrattrs` are public;
//! the enrollment routes authenticate the client themselves (TLS client certificate, or HTTP
//! Basic for the initial enrollment when `est_require_client_cert = false`).

mod cacerts;
mod csrattrs;
mod enroll;

use actix_web::{HttpResponse, http::header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub(crate) use cacerts::get_cacerts;
pub(crate) use csrattrs::get_csrattrs;
#[cfg(test)]
pub(crate) use enroll::simple_reenroll;
pub(crate) use enroll::{post_simpleenroll, post_simplereenroll};

/// Build a `200 OK` response whose body is the base64 encoding of `der`
/// (RFC 7030 §4.1.3 / §4.2.3 `Content-Transfer-Encoding: base64`).
fn base64_response(content_type: &str, der: &[u8]) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, content_type.to_owned()))
        .insert_header(("Content-Transfer-Encoding", "base64"))
        .body(STANDARD.encode(der))
}

/// A plain-text error response (RFC 7030 §4.2.3: a response without a PKI content type
/// carries a human-readable message).
fn plain_response(status: actix_web::http::StatusCode, message: &str) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .body(message.to_owned())
}
