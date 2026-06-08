use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;

use crate::{
    config::HsmInstanceParams,
    core::KMS,
    result::{KResult, KResultHelper},
};

/// Determine whether the unique identifier has a crypto-oracle prefix.
///
/// Supports two HSM UID formats:
/// - Old: `hsm::<slot_id>::<key_id>` → prefix = `"hsm"`
/// - New: `hsm::<model>::<slot_id>::<key_id>` → prefix = `"hsm::<model>"`
///
/// The disambiguation is based on the first segment after `"hsm::"`: if it
/// parses as a `usize` it is the old (slot-first) format; otherwise it is
/// the model name.
pub(crate) fn has_prefix(uid: &str) -> Option<&str> {
    if let Some(rest) = uid.strip_prefix("hsm::") {
        if let Some(pos) = rest.find("::") {
            let first_segment = &rest[..pos];
            // Old format: hsm::<slot_id>::<key_id> (slot_id is a number)
            if first_segment.parse::<usize>().is_ok() {
                return Some("hsm");
            }
            // New format: hsm::<model>::<slot>::<key> → prefix = "hsm::<model>"
            return Some(&uid[..5 + pos]);
        }
    }
    None
}

/// Resolve a human-readable HSM model label from a routing prefix.
///
/// Searches the configured `hsm_instances` for an entry whose `prefix` matches
/// the given prefix and returns its `model` field (e.g. `"softhsm2"`).
/// Falls back to the prefix string itself when no matching instance is found,
/// ensuring call sites always get a usable label without panicking.
///
/// # Arguments
/// * `hsm_instances` — the slice from `ServerParams::hsm_instances`
/// * `prefix` — a routing prefix as returned by [`has_prefix`]
pub(crate) fn hsm_model_from_prefix<'a>(
    hsm_instances: &'a [HsmInstanceParams],
    prefix: &'a str,
) -> &'a str {
    hsm_instances
        .iter()
        .find(|i| i.prefix == prefix)
        .map_or(prefix, |i| i.model.as_str())
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn make_instance(prefix: &str, model: &str) -> HsmInstanceParams {
        HsmInstanceParams {
            model: model.to_owned(),
            admin: vec![],
            slot_passwords: HashMap::new(),
            prefix: prefix.to_owned(),
        }
    }

    #[test]
    fn test_hsm_model_legacy_prefix() {
        // Legacy format: UID "hsm::<slot>::<key>" → prefix == "hsm"
        let instances = vec![make_instance("hsm", "softhsm2")];
        assert_eq!(hsm_model_from_prefix(&instances, "hsm"), "softhsm2");
    }

    #[test]
    fn test_hsm_model_new_format_prefix() {
        // New format: UID "hsm::softhsm2::<slot>::<key>" → prefix == "hsm::softhsm2"
        let instances = vec![make_instance("hsm::softhsm2", "softhsm2")];
        assert_eq!(
            hsm_model_from_prefix(&instances, "hsm::softhsm2"),
            "softhsm2"
        );
    }

    #[test]
    fn test_hsm_model_second_instance() {
        // Multiple instances; prefix selects the correct one.
        let instances = vec![
            make_instance("hsm::softhsm2", "softhsm2"),
            make_instance("hsm::utimaco", "utimaco"),
        ];
        assert_eq!(hsm_model_from_prefix(&instances, "hsm::utimaco"), "utimaco");
    }

    #[test]
    fn test_hsm_model_fallback_to_prefix_when_unknown() {
        // Unknown prefix with empty instance list → falls back to the prefix itself.
        let instances: Vec<HsmInstanceParams> = vec![];
        assert_eq!(
            hsm_model_from_prefix(&instances, "hsm::unknown"),
            "hsm::unknown"
        );
    }
}
