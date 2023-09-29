use tracing::debug;
use x509_parser::{
    oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER},
    prelude::{ParsedExtension, X509Certificate},
    revocation_list::CertificateRevocationList,
    x509::X509Name,
};

use crate::{error::KmsError, result::KResult};

/// The function `get_crl_authority_key_identifier` retrieves the key identifier
/// from the Authority Key Identifier extension of an X.509 certificate revocation
/// list (CRL).
///
/// Arguments:
///
/// * `x509_crl`: The `x509_crl` parameter is of type
/// `CertificateRevocationList<'_>`. It represents an X.509 certificate revocation
/// list.
///
/// Returns:
///
/// The key identifier in hex encoding
pub(crate) fn get_crl_authority_key_identifier(
    x509_crl: &CertificateRevocationList<'_>,
) -> Option<String> {
    x509_crl
        .extensions()
        .iter()
        .find(|&ext| ext.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .and_then(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => Some(aki),
            _ => None,
        })
        .and_then(|aki| aki.key_identifier.as_ref().map(|ki| hex::encode(ki.0)))
}

/// The function `get_common_name` retrieves the first common name from an X509
/// certificate's name field.
///
/// Arguments:
///
/// * `name`: The `name` parameter is of type `X509Name<'_>`. It represents an X.509
/// certificate name, which is a collection of attributes that identify the subject
/// of the certificate. In this function, the `name` parameter is used to extract
/// the common name attribute from the certificate.
///
/// Returns:
///
/// The Common Name.
pub(crate) fn get_common_name(name: &X509Name<'_>) -> KResult<String> {
    // Warning: implementation choice done here:
    // - no Common Name on a X509 certificate is forbidden
    // - multiple Common Name on a X509 certificate is forbidden...

    debug!("get_common_name: name: {}", name);
    let common_name = name
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or(KmsError::Certificate(
            "Cannot get first common name".to_string(),
        ))?;
    Ok(common_name.to_string())
}

/// The function `get_certificate_subject_key_identifier` returns the subject key
/// identifier of an X.509 certificate, encoded as a hexadecimal string.
///
/// Arguments:
///
/// * `x509`: An `X509Certificate` object, which represents an X.509 certificate.
///
/// Returns:
///
/// The Subject Key Identifier (if exists) of the X.509 certificate
pub(crate) fn get_certificate_subject_key_identifier(
    x509: &X509Certificate<'_>,
) -> KResult<Option<String>> {
    match x509.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)? {
        Some(ski) => match &ski.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => Ok(Some(hex::encode(ki.0))),
            _ => Ok(None),
        },
        None => Ok(None),
    }
}
pub(crate) fn get_certificate_authority_subject_key_identifier(
    x509: &X509Certificate<'_>,
) -> KResult<Option<String>> {
    match x509.get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)? {
        Some(ski) => match &ski.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => Ok(Some(hex::encode(ki.0))),
            _ => Ok(None),
        },
        None => Ok(None),
    }
}
