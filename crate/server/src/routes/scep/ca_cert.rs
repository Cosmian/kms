//! `GetCACert` (RFC 8894 §4.2).

use actix_web::HttpResponse;
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::scep_cms::certs_only_der;

use crate::{core::KMS, error::KmsError, result::KResult, routes::enrollment::load_ca_chain};

/// Return the CA certificate: raw DER when the CA is a root (§4.2.1.1), otherwise a degenerate
/// `SignedData` carrying the chain (§4.2.1.2). Responses are raw binary, not base64.
pub(super) async fn get_ca_cert(kms: &KMS) -> KResult<HttpResponse> {
    let ca_uid = kms
        .params
        .scep_ca_uid
        .as_deref()
        .ok_or_else(|| KmsError::ServerError("SCEP enabled without scep_ca_uid".to_owned()))?;
    let chain = load_ca_chain(kms, ca_uid).await?;
    match chain.as_slice() {
        [ca] => Ok(HttpResponse::Ok()
            .content_type("application/x-x509-ca-cert")
            .body(ca.to_der()?)),
        _ => Ok(HttpResponse::Ok()
            .content_type("application/x-x509-ca-ra-cert")
            .body(certs_only_der(&chain)?)),
    }
}
