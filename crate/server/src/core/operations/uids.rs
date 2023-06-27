use cosmian_kmip::kmip::kmip_types::StateEnumeration;
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationTypes};

use crate::{
    core::KMS,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// This functions tries to determine the object uid form a set of tags passed in an identifier.
/// If the user is not the owner, it must have been granted access to the given OperationType.
///
/// If the identifier is not a set of tags, a None is returned.
/// If the set of tags resolve to zero or more than one object uid,
/// an error is returned.
pub async fn uid_from_identifier_tags(
    kms: &KMS,
    identifier: &str,
    user: &str,
    operation_type: ObjectOperationTypes,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Option<String>> {
    // check if the identifier is actually a set of tags
    if !identifier.starts_with('[') {
        return Ok(None)
    }

    let tags: Vec<String> =
        serde_json::from_str(identifier).with_context(|| format!("Invalid tags: {identifier}"))?;
    // find the key(s) that matches the tags
    // the user must be the owner or have decrypt permissions
    let uids = kms
        .db
        .find_from_tags(&tags, Some(user.to_owned()), params)
        .await?
        .into_iter()
        .filter(|(_unique_identifier, owner, state, permissions)| {
            owner == user
                || (*state == StateEnumeration::Active
                    && permissions.iter().any(|p| *p == operation_type))
        })
        .map(|(unique_identifier, _, _, _)| unique_identifier)
        .collect::<Vec<_>>();
    // there must only be one matching key
    match uids.len() {
        0 => kms_bail!("No matching key for tags"),
        1 => Ok(Some(uids[0].clone())),
        _ => {
            kms_bail!("Multiple matching keys for tags")
        }
    }
}
