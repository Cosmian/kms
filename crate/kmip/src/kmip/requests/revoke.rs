use crate::{
    kmip::{
        kmip_operations::Revoke,
        kmip_types::{RevocationReason, UniqueIdentifier},
    },
    KmipError,
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
