//! `GET /.well-known/est/csrattrs` (RFC 7030 §4.5).

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_logger::info;

use super::base64_response;
use crate::{core::KMS, result::KResult};

/// DER of `CsrAttrs ::= SEQUENCE { OBJECT IDENTIFIER id-pkcs9-at-extensionRequest }`
/// (RFC 7030 §4.5.2): the client is invited to send extension requests in its CSR.
const CSR_ATTRS_EXTENSION_REQUEST: [u8; 13] = [
    0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
];

/// Describe the attributes the server would like in a CSR. Public (§4.5).
///
/// Answers `204 No Content` when no template is configured: the server is enabled but has
/// no guidance to add. Template constraints are enforced after submission.
#[get("/.well-known/est/csrattrs")]
pub(crate) async fn get_csrattrs(_req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!("GET /.well-known/est/csrattrs");
    if kms.params.est_template.is_none() {
        return Ok(HttpResponse::NoContent().finish());
    }
    Ok(base64_response(
        "application/csrattrs",
        &CSR_ATTRS_EXTENSION_REQUEST,
    ))
}
