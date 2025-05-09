use crate::{
    KmipError,
    kmip_0::kmip_types::RevocationReason,
    kmip_2_1::{kmip_operations::Revoke, kmip_types::UniqueIdentifier},
};

/// Build a `Revoke` request to revoke the key identified by `unique_identifier`
pub fn build_revoke_key_request(
    unique_identifier: &str,
    revocation_reason: RevocationReason,
) -> Result<Revoke, KmipError> {
    Ok(Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
        revocation_reason,
        compromise_occurrence_date: None,
    })
}
