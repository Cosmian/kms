use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
    LinkType, UniqueIdentifier,
};
use cosmian_logger::trace;

use crate::{
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

// ─── Keyset Resolution ───────────────────────────────────────────────────────

/// The result of parsing a keyset identifier (`name@version` syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeysetVersion {
    /// `name@latest` — resolve to the key with `rotate_latest=true`
    Latest,
    /// `name@first` or `name@0` — resolve to generation 0
    First,
    /// `name@N` — resolve to a specific generation number
    Generation(i32),
    /// Bare `name` (no `@` suffix) — interpretation depends on operation mode
    Bare,
}

/// Parsed keyset reference.
#[derive(Debug, Clone)]
pub(crate) struct KeysetRef {
    pub name: String,
    pub version: KeysetVersion,
}

/// Returns `true` if the string looks like a UUID (8-4-4-4-12 hex pattern).
fn looks_like_uuid(s: &str) -> bool {
    // Quick length check: standard UUID is 36 chars
    if s.len() != 36 {
        return false;
    }
    s.chars().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Try to parse an identifier as a keyset reference.
///
/// A keyset reference is recognized when:
/// - It is NOT a tag JSON (`[...]`)
/// - It is NOT an HSM prefix (`hsm::...`)
/// - It is NOT a UUID
/// - It contains `@` (explicit version) OR is a bare name (fallback resolution)
///
/// Returns `None` if the identifier doesn't match keyset syntax.
pub(crate) fn parse_keyset_identifier(identifier: &str) -> Option<KeysetRef> {
    // Skip tags and UUIDs.
    // HSM UIDs with an `@` suffix ARE valid keyset references: the user addresses
    // the keyset by its rotate_name, not by an hsm:: UID.
    if identifier.starts_with('[') {
        return None;
    }
    // A bare `hsm::...` UID (no `@`) is a direct key address, not a keyset ref.
    if identifier.starts_with("hsm::") && !identifier.contains('@') {
        return None;
    }

    if let Some(at_pos) = identifier.rfind('@') {
        let name = &identifier[..at_pos];
        let version_str = &identifier[at_pos + 1..];

        // If the part before @ looks like a UUID, it's not a keyset reference
        if looks_like_uuid(name) {
            return None;
        }

        // Empty name is not valid
        if name.is_empty() {
            return None;
        }

        let version = match version_str {
            "latest" => KeysetVersion::Latest,
            "first" => KeysetVersion::First,
            s => {
                if let Ok(n) = s.parse::<i32>() {
                    if n == 0 {
                        KeysetVersion::First
                    } else {
                        KeysetVersion::Generation(n)
                    }
                } else {
                    // Invalid version specifier — not a keyset reference
                    return None;
                }
            }
        };

        Some(KeysetRef {
            name: name.to_owned(),
            version,
        })
    } else {
        // No `@` — could be a bare keyset name if it's not a UUID
        if looks_like_uuid(identifier) {
            return None;
        }
        // It could be a plain UID that isn't a UUID (e.g. user-chosen IDs).
        // We return a Bare keyset reference — the caller will attempt DB lookup
        // and fall back to direct UID if the keyset name doesn't exist.
        Some(KeysetRef {
            name: identifier.to_owned(),
            version: KeysetVersion::Bare,
        })
    }
}

/// Resolve a keyset identifier to a single UID (for encrypt/sign operations).
///
/// For `@latest` or `Bare` mode, resolves to the key with `rotate_latest=true`.
/// If no key has `rotate_latest=true`, falls back to finding any key with that
/// `rotate_name` and picks the one with the highest generation (handles the case
/// where a key has `rotate_name` set but hasn't been rotated yet).
///
/// For `@first` or `@N`, resolves to the key with the matching generation.
///
/// Returns `None` if the keyset name doesn't match any object.
pub(crate) async fn resolve_keyset_to_single_uid(
    keyset_ref: &KeysetRef,
    kms: &KMS,
    user: &str,
) -> KResult<Option<String>> {
    let (generation, latest) = match &keyset_ref.version {
        KeysetVersion::Latest | KeysetVersion::Bare => (None, Some(true)),
        KeysetVersion::First => (Some(0), None),
        KeysetVersion::Generation(n) => (Some(*n), None),
    };

    let mut results = kms
        .database
        .find_by_rotate_name(&keyset_ref.name, generation, latest, user)
        .await?;

    // Fallback: if looking for @latest but no key has rotate_latest=true,
    // search by name only and pick the highest generation. This handles keys
    // that have rotate_name set but haven't been rotated yet.
    if results.is_empty() && latest == Some(true) {
        results = kms
            .database
            .find_by_rotate_name(&keyset_ref.name, None, None, user)
            .await?;
    }

    match results.len() {
        0 => Ok(None),
        1 => Ok(Some(
            results
                .into_iter()
                .next()
                .map(|(uid, _)| uid)
                .unwrap_or_default(),
        )),
        _ => {
            // Multiple matches — take the one with highest generation
            let best = results
                .into_iter()
                .max_by_key(|(_, attrs)| attrs.rotate_generation.unwrap_or(0));
            Ok(best.map(|(uid, _)| uid))
        }
    }
}

/// Walk the keyset rotation chain from the latest key backward.
///
/// Starts from the key with `rotate_latest=true` for the given `rotate_name`,
/// then follows `ReplacedObjectLink` backward, collecting UIDs in newest-to-oldest
/// order.
///
/// Stops when:
/// - No more `ReplacedObjectLink` is found (reached the original key)
/// - The `max_depth` limit is reached
/// - A cycle is detected
///
/// Returns the ordered list of UIDs to try for decryption.
pub(crate) async fn walk_keyset_chain(
    keyset_name: &str,
    kms: &KMS,
    user: &str,
    max_depth: u32,
) -> KResult<Vec<String>> {
    // Find the latest key in the chain (prefer rotate_latest=true)
    let mut results = kms
        .database
        .find_by_rotate_name(keyset_name, None, Some(true), user)
        .await?;

    // Fallback: if no key has rotate_latest=true, search by name only
    if results.is_empty() {
        results = kms
            .database
            .find_by_rotate_name(keyset_name, None, None, user)
            .await?;
    }

    let Some((latest_uid, _)) = results
        .into_iter()
        .max_by_key(|(_, attrs)| attrs.rotate_generation.unwrap_or(0))
    else {
        return Ok(vec![]);
    };

    // HSM keys store all rotation metadata in PKCS#11 attributes — there are no
    // ReplacedObjectLink back-pointers. Fetch every generation and sort newest-first.
    if latest_uid.starts_with("hsm::") {
        let all_results = kms
            .database
            .find_by_rotate_name(keyset_name, None, None, user)
            .await?;
        let mut all_pairs: Vec<(String, i32)> = all_results
            .into_iter()
            .map(|(uid, attrs)| (uid, attrs.rotate_generation.unwrap_or(0)))
            .collect();
        all_pairs.sort_by(|a, b| b.1.cmp(&a.1));
        let chain: Vec<String> = all_pairs.into_iter().map(|(uid, _)| uid).collect();
        trace!(
            "walk_keyset_chain: HSM keyset '{}' has {} keys in chain",
            keyset_name,
            chain.len()
        );
        return Ok(chain);
    }

    let mut chain = vec![latest_uid.clone()];
    let mut current_uid = latest_uid;
    let mut visited: HashSet<String> = chain.iter().cloned().collect();

    for _ in 1..max_depth {
        // Retrieve the current object's attributes to find ReplacedObjectLink
        let Some(owm) = kms.database.retrieve_object(&current_uid).await? else {
            break;
        };

        // Look for ReplacedObjectLink (points backward to the older key)
        let prev_uid = owm
            .attributes()
            .get_link(LinkType::ReplacedObjectLink)
            .map(|link| link.to_string());

        let Some(prev_uid) = prev_uid else {
            break; // End of chain
        };

        // Cycle detection
        if !visited.insert(prev_uid.clone()) {
            trace!(
                "walk_keyset_chain: cycle detected at {} for keyset '{}'",
                prev_uid, keyset_name
            );
            break;
        }

        chain.push(prev_uid.clone());
        current_uid = prev_uid;
    }

    trace!(
        "walk_keyset_chain: keyset '{}' has {} keys in chain",
        keyset_name,
        chain.len()
    );

    Ok(chain)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keyset_latest() {
        let r = parse_keyset_identifier("my-keys@latest").expect("should parse");
        assert_eq!(r.name, "my-keys");
        assert_eq!(r.version, KeysetVersion::Latest);
    }

    #[test]
    fn test_parse_keyset_first() {
        let r = parse_keyset_identifier("my-keys@first").expect("should parse");
        assert_eq!(r.name, "my-keys");
        assert_eq!(r.version, KeysetVersion::First);

        let r = parse_keyset_identifier("my-keys@0").expect("should parse");
        assert_eq!(r.name, "my-keys");
        assert_eq!(r.version, KeysetVersion::First);
    }

    #[test]
    fn test_parse_keyset_generation() {
        let r = parse_keyset_identifier("my-keys@3").expect("should parse");
        assert_eq!(r.name, "my-keys");
        assert_eq!(r.version, KeysetVersion::Generation(3));
    }

    #[test]
    fn test_parse_keyset_bare() {
        let r = parse_keyset_identifier("my-production-key").expect("should parse");
        assert_eq!(r.name, "my-production-key");
        assert_eq!(r.version, KeysetVersion::Bare);
    }

    #[test]
    fn test_parse_uuid_not_keyset() {
        assert!(parse_keyset_identifier("550e8400-e29b-41d4-a716-446655440000").is_none());
    }

    #[test]
    fn test_parse_tags_not_keyset() {
        assert!(parse_keyset_identifier("[\"tag1\",\"tag2\"]").is_none());
    }

    #[test]
    fn test_parse_hsm_not_keyset() {
        assert!(parse_keyset_identifier("hsm::softhsm2::0::my-key").is_none());
    }

    #[test]
    fn test_parse_invalid_version() {
        // "abc" after @ is not a valid version specifier
        assert!(parse_keyset_identifier("my-key@abc").is_none());
    }

    #[test]
    fn test_parse_uuid_with_at() {
        // A UUID followed by @latest should NOT be treated as keyset
        assert!(parse_keyset_identifier("550e8400-e29b-41d4-a716-446655440000@latest").is_none());
    }
}
