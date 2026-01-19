use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;

use crate::{
    core::KMS,
    result::{KResult, KResultHelper},
};

pub(super) const UID_PREFIX_SEPARATOR: &str = "::";

/// Determine whether the unique identifier has a prefix or not
/// # Arguments
///  * `uid` - A string slice representing the unique identifier
/// # Returns
/// * `Option` - A tuple of two string slices, the first one is the prefix and the second one is the full uid
pub(super) fn has_prefix(uid: &str) -> Option<&str> {
    uid.split_once(UID_PREFIX_SEPARATOR)
        .map(|(prefix, _)| prefix)
}

/// Determine the list of possible UIDs from a Unique Identifier,
/// that may contain tags
/// # Arguments
/// * `unique_identifier` - A `UniqueIdentifier` object
/// * `kms` - A reference to the KMS object
/// * `params` - An optional reference to the `ExtraStoreParams` object
/// # Returns
/// * `KResult` - A `HashSet` of strings representing the possible UIDs
pub(super) async fn uids_from_unique_identifier(
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
) -> KResult<HashSet<String>> {
    let uid_or_tags = unique_identifier
        .as_str()
        .context("The unique identifier or tags must be a string")?;
    if uid_or_tags.starts_with('[') {
        // tags
        let tags: HashSet<String> = serde_json::from_str(uid_or_tags)?;
        return Ok(kms.database.list_uids_for_tags(&tags).await?);
    }
    Ok(HashSet::from([uid_or_tags.to_owned()]))
}
