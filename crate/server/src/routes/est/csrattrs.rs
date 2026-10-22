//! `GET /.well-known/est/csrattrs` (RFC 7030 §4.5).

use std::{borrow::Cow, sync::Arc};

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::oid::asn1_object;
use cosmian_logger::info;
use openssl::nid::Nid;
use x509_parser::asn1_rs::{Oid, Sequence, ToDer};

use super::base64_response;
use crate::{core::KMS, error::KmsError, result::KResult};

/// DER of `CsrAttrs ::= SEQUENCE { OBJECT IDENTIFIER id-pkcs9-at-extensionRequest }`
/// (RFC 7030 §4.5.2): the client is invited to send extension requests in its CSR.
fn csr_attrs_extension_request() -> KResult<Vec<u8>> {
    let oid = asn1_object(Nid::EXT_REQ)?;
    let oid_der = Oid::new(Cow::Borrowed(oid.as_slice()))
        .to_der_vec()
        .map_err(|e| KmsError::ServerError(e.to_string()))?;
    Sequence::new(Cow::Owned(oid_der))
        .to_der_vec()
        .map_err(|e| KmsError::ServerError(e.to_string()))
}

/// Describe the attributes the server would like in a CSR. Public (§4.5).
///
/// Template constraints are enforced after submission.
#[get("/.well-known/est/csrattrs")]
pub(crate) async fn get_csrattrs(_req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!("GET /.well-known/est/csrattrs");
    Ok(base64_response(
        "application/csrattrs",
        &csr_attrs_extension_request()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::csr_attrs_extension_request;

    /// The DER built from `Nid::EXT_REQ` is byte-for-byte the historical literal.
    #[test]
    fn extension_request_der_is_exact() {
        assert_eq!(
            csr_attrs_extension_request().ok().as_deref(),
            Some(
                [
                    0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E
                ]
                .as_slice()
            )
        );
    }
}
