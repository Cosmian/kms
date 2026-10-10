//! SCEP (Simple Certificate Enrollment Protocol, RFC 8894) endpoint.
//!
//! A single resource dispatches on the `operation` query parameter (RFC 8894 §4.1):
//!
//! ```text
//! GET  /scep?operation=GetCACaps
//! GET  /scep?operation=GetCACert
//! GET  /scep?operation=PKIOperation&message=<base64>
//! POST /scep?operation=PKIOperation          (body: application/x-pki-message)
//! ```
//!
//! Authentication happens inside the CMS `pkiMessage` (RFC 8894 §2.3), so no HTTP-level
//! authentication is applied. The route answers 404 unless `scep_enabled = true`.

mod ca_caps;
mod ca_cert;
mod pki_operation;

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, get, post,
    web::{Bytes, Data, Query},
};
use serde::Deserialize;

use crate::{core::KMS, result::KResult};

/// Query string of a SCEP request (RFC 8894 §4.1).
#[derive(Deserialize)]
pub(crate) struct ScepQuery {
    operation: Option<String>,
    message: Option<String>,
}

fn bad_request(message: &str) -> HttpResponse {
    HttpResponse::BadRequest()
        .content_type("text/plain; charset=utf-8")
        .body(message.to_owned())
}

/// Handle `GET /scep?operation=...`.
#[get("/scep")]
pub(crate) async fn scep_get(
    _req: HttpRequest,
    kms: Data<Arc<KMS>>,
    query: Query<ScepQuery>,
) -> KResult<HttpResponse> {
    if !kms.params.scep_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    match query.operation.as_deref() {
        Some("GetCACaps") => Ok(ca_caps::get_ca_caps()),
        Some("GetCACert") => ca_cert::get_ca_cert(&kms).await,
        Some("PKIOperation") => match query.message.as_deref() {
            Some(message) => match pki_operation::decode_get_message(message) {
                Ok(der) => pki_operation::pki_operation(&kms, &der).await,
                Err(e) => Ok(bad_request(&e)),
            },
            None => Ok(bad_request("missing `message` parameter")),
        },
        Some(other) => Ok(bad_request(&format!("unsupported SCEP operation: {other}"))),
        None => Ok(bad_request("missing `operation` parameter")),
    }
}

/// Handle `POST /scep?operation=PKIOperation`.
#[post("/scep")]
pub(crate) async fn scep_post(
    _req: HttpRequest,
    kms: Data<Arc<KMS>>,
    query: Query<ScepQuery>,
    body: Bytes,
) -> KResult<HttpResponse> {
    if !kms.params.scep_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    match query.operation.as_deref() {
        Some("PKIOperation") => pki_operation::pki_operation(&kms, &body).await,
        Some(other) => Ok(bad_request(&format!(
            "operation {other} is not supported over POST"
        ))),
        None => Ok(bad_request("missing `operation` parameter")),
    }
}
