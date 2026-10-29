//! `GET /.well-known/est/csrattrs` (RFC 7030 §4.5).

use std::{borrow::Cow, sync::Arc};

use actix_web::{HttpRequest, HttpResponse, get, web::Data};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::oid::asn1_object;
use cosmian_logger::info;
use openssl::{asn1::Asn1Object, nid::Nid};
use x509_parser::asn1_rs::{Oid, Sequence, Set, ToDer};

use super::base64_response;
use crate::{
    core::{
        KMS,
        operations::certify::template::{CertTemplate, canonical_curve},
    },
    error::KmsError,
    result::KResult,
};

fn der_error(e: impl std::fmt::Display) -> KmsError {
    KmsError::ServerError(format!("csrattrs encoding: {e}"))
}

fn oid_der(oid: &Asn1Object) -> KResult<Vec<u8>> {
    Oid::new(Cow::Borrowed(oid.as_slice()))
        .to_der_vec()
        .map_err(der_error)
}

/// `Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ... }` (`values` is the DER
/// of the set members).
fn attribute(attr_type: Nid, values: Vec<u8>) -> KResult<Vec<u8>> {
    let mut content = oid_der(&asn1_object(attr_type)?)?;
    content.extend(
        Set::new(Cow::Owned(values))
            .to_der_vec()
            .map_err(der_error)?,
    );
    Sequence::new(Cow::Owned(content))
        .to_der_vec()
        .map_err(der_error)
}

/// DER of the `CsrAttrs` (RFC 7030 §4.5.2) for `template`: `extensionRequest` (the client is
/// invited to send extension requests), then the key types the CA accepts, as RFC 9908 §3.2
/// key attributes: `rsaEncryption` with the minimum modulus size, and `id-ecPublicKey` with
/// the allowed curves. Either key type is accepted.
fn csr_attrs(template: &CertTemplate) -> KResult<Vec<u8>> {
    let mut content = oid_der(&asn1_object(Nid::EXT_REQ)?)?;
    content.extend(attribute(
        Nid::RSAENCRYPTION,
        template.min_rsa_key_bits.to_der_vec().map_err(der_error)?,
    )?);
    let mut curves = Vec::new();
    for name in &template.allowed_ec_curves {
        // short names are case-sensitive; template matching is not (see `canonical_curve`)
        let curve = Asn1Object::from_str(&canonical_curve(name))
            .or_else(|_| Asn1Object::from_str(name.trim()))
            .map_err(|e| {
                KmsError::ServerError(format!(
                    "template '{}': unknown EC curve '{name}': {e}",
                    template.name
                ))
            })?;
        curves.extend(oid_der(&curve)?);
    }
    content.extend(attribute(Nid::X9_62_ID_ECPUBLICKEY, curves)?);
    Sequence::new(Cow::Owned(content))
        .to_der_vec()
        .map_err(der_error)
}

/// Describe the attributes and key types the server wants in a CSR (the `est_template`
/// key constraints). Public (§4.5).
///
/// The other template constraints (subject, SANs, EKUs) are enforced after submission.
#[get("/.well-known/est/csrattrs")]
pub(crate) async fn get_csrattrs(_req: HttpRequest, kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    if !kms.params.est_enabled {
        return Ok(HttpResponse::NotFound().finish());
    }
    info!("GET /.well-known/est/csrattrs");
    let template = kms
        .params
        .est_template
        .as_ref()
        .ok_or_else(|| KmsError::ServerError("EST enabled without est_template".to_owned()))?;
    Ok(base64_response(
        "application/csrattrs",
        &csr_attrs(template)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{CertTemplate, csr_attrs};

    /// The default template's response, byte for byte.
    #[test]
    fn csr_attrs_der_carries_the_template_key_requirements() {
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x30, 0x43,
            // extensionRequest (1.2.840.113549.1.9.14)
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
            // rsaEncryption, SET { INTEGER 2048 }
            0x30, 0x11,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x31, 0x04, 0x02, 0x02, 0x08, 0x00,
            // id-ecPublicKey, SET { P-256, P-384, P-521 }
            0x30, 0x23,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x31, 0x18,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23,
        ];
        assert_eq!(
            csr_attrs(&CertTemplate::default()).ok().as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn csr_attrs_follow_the_template() {
        let template = CertTemplate {
            min_rsa_key_bits: 3072,
            allowed_ec_curves: vec!["P-384".to_owned()],
            ..CertTemplate::default()
        };
        let der = csr_attrs(&template).ok();
        let der = der.as_deref().unwrap_or_default();
        let contains = |needle: &[u8]| der.windows(needle.len()).any(|w| w == needle);
        // SET { INTEGER 3072 }, SET { secp384r1 }
        assert!(contains(&[0x31, 0x04, 0x02, 0x02, 0x0C, 0x00]));
        assert!(contains(&[
            0x31, 0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
        ]));
    }
}
