//! Characterization tests for `Attributes::ensure_X509_or_none`.

use pkcs11_sys::CKC_X_509;

use super::{Attribute, Attributes};
use crate::ModuleError;

fn call_ensure_x509_or_none(attributes: &Attributes) -> Result<(), ModuleError> {
    attributes.ensure_X509_or_none()
}

#[test]
fn characterization_ensure_x509_or_none_empty_attributes() {
    let attrs = Attributes::from(vec![]);
    call_ensure_x509_or_none(&attrs).unwrap();
}

#[test]
fn characterization_ensure_x509_or_none_valid_x509() {
    let attrs = Attributes::from(vec![Attribute::CertificateType(CKC_X_509)]);
    call_ensure_x509_or_none(&attrs).unwrap();
}

#[test]
fn characterization_ensure_x509_or_none_unsupported_cert_type() {
    let attrs = Attributes::from(vec![Attribute::CertificateType(999)]);
    let err = call_ensure_x509_or_none(&attrs).unwrap_err();
    assert_eq!(
        err.to_string(),
        "ensure_X509_or_none: support for certificate type: 999 is not implemented".to_owned()
    );
}

#[test]
fn characterization_ensure_x509_or_none_other_attribute_value() {
    let attrs = Attributes::from(vec![Attribute::CertificateCategory(1)]);
    call_ensure_x509_or_none(&attrs).unwrap();
}
