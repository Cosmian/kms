//! `GET /.well-known/est/cacerts` (RFC 7030 §4.1).

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::scep_cms::certs_only_der;
use cosmian_logger::info;

use super::base64_response;
use crate::{core::KMS, error::KmsError, result::KResult, routes::enrollment::load_ca_chain};

/// Distribute the CA certificate chain as a degenerate (certs-only) CMS `SignedData`
/// (RFC 7030 §4.1.3). No client authentication is required (§4.1.2).
#[get("/.well-known/est/cacerts")]
pub(crate) async fn get_cacerts(_req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!("GET /.well-known/est/cacerts");
    let ca_uid = kms
        .params
        .est_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_ca_uid".to_owned()))?;
    let chain = load_ca_chain(&kms, ca_uid).await?;
    let der = certs_only_der(&chain)?;
    Ok(base64_response("application/pkcs7-mime", &der))
}
