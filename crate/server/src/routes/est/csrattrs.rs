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

/// `Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ... }` with the single
/// DER-encoded `value`: a singleton SET OF needs no X.690 §11.6 sorting, so it is DER.
fn attribute(attr_type: Nid, value: Vec<u8>) -> KResult<Vec<u8>> {
    let mut content = oid_der(&asn1_object(attr_type)?)?;
    content.extend(
        Set::new(Cow::Owned(value))
            .to_der_vec()
            .map_err(der_error)?,
    );
    Sequence::new(Cow::Owned(content))
        .to_der_vec()
        .map_err(der_error)
}

/// DER of the `CsrAttrs` (RFC 7030 §4.5.2) for `template`: `extensionRequest` (the client is
/// invited to send extension requests), then exactly one RFC 9908 §3.2 key-type attribute:
/// `id-ecPublicKey` with the first (operator-preferred) curve of `allowed_ec_curves`, or, when
/// the template lists no curve, `rsaEncryption` with the minimum modulus size. The attribute is
/// a hint: enrollment still accepts any key the template allows.
fn csr_attrs(template: &CertTemplate) -> KResult<Vec<u8>> {
    let mut content = oid_der(&asn1_object(Nid::EXT_REQ)?)?;
    let key_type = match template.allowed_ec_curves.first() {
        Some(name) => {
            // short names are case-sensitive; template matching is not (see `canonical_curve`)
            let curve = Asn1Object::from_str(&canonical_curve(name))
                .or_else(|_| Asn1Object::from_str(name.trim()))
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "template '{}': unknown EC curve '{name}': {e}",
                        template.name
                    ))
                })?;
            attribute(Nid::X9_62_ID_ECPUBLICKEY, oid_der(&curve)?)?
        }
        None => attribute(
            Nid::RSAENCRYPTION,
            template.min_rsa_key_bits.to_der_vec().map_err(der_error)?,
        )?,
    };
    content.extend(key_type);
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
    use der::{Any, Decode, Encode, Tag, Tagged, asn1::ObjectIdentifier};
    use x509_cert::attr::Attribute;

    use super::{CertTemplate, KmsError, csr_attrs, der_error};
    use crate::result::KResult;

    const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    /// Strictly DER-decode a `CsrAttrs` and return its single key-type attribute. `der` sorts
    /// SET OF members on decode, so a non-DER (e.g. unsorted) encoding does not re-encode to
    /// the same bytes. Errors unless there is exactly one attribute with one value (RFC 9908
    /// §3.2).
    fn single_key_type_attribute(csr_attrs: &[u8]) -> KResult<Attribute> {
        let items = Vec::<Any>::from_der(csr_attrs).map_err(der_error)?;
        let mut attributes = Vec::new();
        for item in &items {
            if item.tag() == Tag::Sequence {
                let attribute: Attribute = item.decode_as().map_err(der_error)?;
                if attribute.to_der().map_err(der_error)? != item.to_der().map_err(der_error)? {
                    return Err(der_error("attribute is not DER"));
                }
                attributes.push(attribute);
            }
        }
        match <[Attribute; 1]>::try_from(attributes) {
            Ok([attribute]) if attribute.values.len() == 1 => Ok(attribute),
            _ => Err(KmsError::ServerError(
                "expected exactly one key-type attribute with one value".to_owned(),
            )),
        }
    }

    /// The `(type, DER of the SET OF values)` of the single key-type attribute of `template`.
    fn key_type(template: &CertTemplate) -> Option<(ObjectIdentifier, Vec<u8>)> {
        let attribute = single_key_type_attribute(&csr_attrs(template).ok()?).ok()?;
        Some((attribute.oid, attribute.values.to_der().ok()?))
    }

    /// The default template's response, byte for byte: P-256, the first allowed curve.
    #[test]
    fn csr_attrs_der_carries_the_template_key_requirements() {
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x30, 0x22,
            // extensionRequest (1.2.840.113549.1.9.14)
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
            // id-ecPublicKey, SET { prime256v1 }
            0x30, 0x15,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x31, 0x0A,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        ];
        let template = CertTemplate::default();
        assert_eq!(csr_attrs(&template).ok().as_deref(), Some(expected));
        assert_eq!(key_type(&template).map(|(oid, _)| oid), Some(EC_PUBLIC_KEY));
    }

    #[test]
    fn csr_attrs_follow_the_template() {
        let ec = CertTemplate {
            min_rsa_key_bits: 3072,
            allowed_ec_curves: vec!["P-384".to_owned(), "prime256v1".to_owned()],
            ..CertTemplate::default()
        };
        // SET { secp384r1 }
        assert_eq!(
            key_type(&ec),
            Some((
                EC_PUBLIC_KEY,
                vec![0x31, 0x07, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
            ))
        );

        let rsa = CertTemplate {
            allowed_ec_curves: Vec::new(),
            ..ec
        };
        // SET { INTEGER 3072 }
        assert_eq!(
            key_type(&rsa),
            Some((RSA_ENCRYPTION, vec![0x31, 0x04, 0x02, 0x02, 0x0C, 0x00]))
        );
    }

    /// The pre-5.29.0 encoding (two key-type attributes, unsorted curve SET) is rejected.
    #[test]
    fn strict_der_check_rejects_the_legacy_encoding() {
        #[rustfmt::skip]
        let legacy: &[u8] = &[
            0x30, 0x43,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
            0x30, 0x11,
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
            0x31, 0x04, 0x02, 0x02, 0x08, 0x00,
            0x30, 0x23,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x31, 0x18,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23,
        ];
        assert!(matches!(
            single_key_type_attribute(legacy),
            Err(KmsError::ServerError(_))
        ));
        // its EC attribute alone also fails: the curve SET OF is not DER-sorted
        let (_, ec_attribute) = legacy.split_at(32);
        assert!(matches!(
            single_key_type_attribute(&[&[0x30, 0x25], ec_attribute].concat()),
            Err(KmsError::ServerError(_))
        ));
    }
}
