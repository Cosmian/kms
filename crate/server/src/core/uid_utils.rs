use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;

use crate::{
    core::KMS,
    result::{KResult, KResultHelper},
};

/// Determine whether the unique identifier has a crypto-oracle prefix.
///
/// The prefix format is `hsm::<model>` (e.g. `hsm::softhsm2`), followed by
/// `::slot::key`.  Returns `Some("hsm::<model>")` when the UID matches this
/// pattern, or `None` for plain database UIDs.
pub(super) fn has_prefix(uid: &str) -> Option<&str> {
    // HSM UIDs: hsm::<model>::<slot>::<key> → prefix = "hsm::<model>"
    if let Some(rest) = uid.strip_prefix("hsm::") {
        if let Some(pos) = rest.find("::") {
            // prefix length = "hsm::".len() + model.len()
            return Some(&uid[..5 + pos]);
        }
    }
    None
}

/// Determine the list of possible UIDs from a Unique Identifier,
/// that may contain tags.
/// # Arguments
/// * `unique_identifier` - A `UniqueIdentifier` object
/// * `kms` - A reference to the KMS object
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
