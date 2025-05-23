use crate::{
    KmipError,
    kmip_2_1::{kmip_operations::Validate, kmip_types::UniqueIdentifier},
};

/// Build a `Validate` request to validate a certificate chain.
pub fn build_validate_certificate_request(
    unique_identifiers: &[String],
    date: Option<String>,
) -> Result<Validate, KmipError> {
    let unique_identifiers = {
        if unique_identifiers.is_empty() {
            None
        } else {
            Some(
                unique_identifiers
                    .iter()
                    .map(|x| UniqueIdentifier::TextString(x.clone()))
                    .collect(),
            )
        }
    };
    Ok(Validate {
        certificate: None,
        unique_identifier: unique_identifiers,
        validity_time: date,
    })
}
