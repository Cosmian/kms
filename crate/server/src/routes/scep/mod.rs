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
//! Both resources are also served under `/scep/pkiclient.exe`: the Windows MDM SCEP (NDES)
//! client appends that suffix to the configured URL.
//!
//! Authentication happens inside the CMS `pkiMessage` (RFC 8894 §2.3), so no HTTP-level
//! authentication is applied. The route answers 404 unless `scep_enabled = true`.

mod ca_caps;
mod ca_cert;
mod pki_operation;

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, routes,
    web::{Data, Payload, Query},
};
use serde::Deserialize;

use crate::{
    core::KMS,
    result::KResult,
    routes::enrollment::{client_ip, read_limited_body},
};

/// Query string of a SCEP request (RFC 8894 §4.1).
#[derive(Deserialize)]
pub(crate) struct ScepQuery {
    operation: Option<String>,
    message: Option<String>,
}

fn bad_request(message: &str) -> HttpResponse {
    HttpResponse::BadRequest()
        .content_type("text/plain; charset=utf-8")
        .insert_header((actix_web::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .body(message.to_owned())
}

/// Handle `GET /scep?operation=...`.
#[routes]
#[get("/scep")]
#[get("/scep/pkiclient.exe")]
pub(crate) async fn scep_get(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    query: Query<ScepQuery>,
) -> KResult<HttpResponse> {
    if !kms.params.scep_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    match query.operation.as_deref() {
        Some("GetCACaps") => Ok(ca_caps::get_ca_caps(
            kms.params.scep_allow_renewal_without_challenge,
        )),
        Some("GetCACert") => ca_cert::get_ca_cert(&kms).await,
        Some("PKIOperation") => match query.message.as_deref() {
            Some(message) => match pki_operation::decode_get_message(message) {
                Ok(der) => pki_operation::pki_operation(&kms, client_ip(&kms, &req), &der).await,
                Err(e) => Ok(bad_request(&e)),
            },
            None => Ok(bad_request("missing `message` parameter")),
        },
        // The value is attacker controlled: never echoed.
        Some(_) => Ok(bad_request("unsupported SCEP operation")),
        None => Ok(bad_request("missing `operation` parameter")),
    }
}

/// Handle `POST /scep?operation=PKIOperation`.
#[routes]
#[post("/scep")]
#[post("/scep/pkiclient.exe")]
pub(crate) async fn scep_post(
    req: HttpRequest,
    kms: Data<Arc<KMS>>,
    query: Query<ScepQuery>,
    payload: Payload,
) -> KResult<HttpResponse> {
    if !kms.params.scep_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    match query.operation.as_deref() {
        Some("PKIOperation") => {
            let body = match read_limited_body(payload).await {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
            pki_operation::pki_operation(&kms, client_ip(&kms, &req), &body).await
        }
        Some(_) => Ok(bad_request("operation not supported over POST")),
        None => Ok(bad_request("missing `operation` parameter")),
    }
}
