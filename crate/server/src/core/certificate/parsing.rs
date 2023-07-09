use tracing::debug;
use x509_parser::{
    oid_registry::{OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER},
    prelude::{ParsedExtension, X509Certificate},
    revocation_list::CertificateRevocationList,
    x509::X509Name,
};

use crate::{error::KmsError, result::KResult};

pub(crate) fn get_crl_authority_key_identifier(
    x509_crl: &CertificateRevocationList<'_>,
) -> KResult<String> {
    let aki_option = x509_crl
        .extensions()
        .iter()
        .find(|&ext| ext.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .and_then(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => Some(aki),
            _ => None,
        });
    let aki = aki_option.ok_or(KmsError::Certificate(
        "Extension Authority Key Identifier not found".to_string(),
    ))?;
    let ki = aki.key_identifier.clone().ok_or(KmsError::Certificate(
        "Authority Key Identifier does not have Key Identifier".to_string(),
    ))?;
    Ok(hex::encode(ki.0))
}

pub(crate) fn get_common_name(name: &X509Name<'_>) -> KResult<String> {
    // Warning: implementation choice done here:
    // - no Common Name on a X509 certificate is forbidden
    // - multiple Common Name on a X509 certificate is forbidden...
    let common_name = name
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or(KmsError::Certificate(
            "Cannot get first common name".to_string(),
        ))?;
    debug!("X.509 Common Name: {}", common_name);
    Ok(common_name.to_string())
}

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
