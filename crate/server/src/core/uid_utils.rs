use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
pub(crate) use cosmian_kms_server_database::reexport::cosmian_kms_interfaces::ObjectHandle;
use cosmian_logger::trace;

use crate::{
    config::HsmInstanceParams, core::KMS, error::KmsError, middlewares::UserId, result::KResult,
};

/// Build an [`ObjectHandle`] from an optional `UniqueIdentifier` request field.
///
/// Extracts and validates the unique identifier from a KMIP request, eliminating the
/// 5-line boilerplate that was repeated at every operation entry-point.
///
/// # Errors
/// - [`KmsError::InvalidRequest`] — if `uid` is `None` or the identifier is not a `TextString`
pub(crate) fn from_request<'a>(
    uid: Option<&'a UniqueIdentifier>,
    op_name: &str,
) -> KResult<ObjectHandle<'a>> {
    let s = uid
        .ok_or_else(|| {
            KmsError::InvalidRequest(format!("{op_name}: the unique identifier is required"))
        })?
        .as_str()
        .ok_or_else(|| {
            KmsError::InvalidRequest(format!("{op_name}: the unique identifier must be a string"))
        })?;
    Ok(ObjectHandle::from(s))
}

/// Interpret an [`ObjectHandle`] as a keyset reference (`name`, `name@latest`, `name@N`, …).
///
/// Returns `None` when the identifier is not keyset syntax (tag JSON, UUID, or an explicit
/// `@N` HSM generation handle). Concentrates keyset classification so callers don't re-parse
/// the raw string.
pub(crate) fn as_keyset_ref(handle: ObjectHandle<'_>) -> Option<KeysetRef> {
    parse_keyset_identifier(handle.as_str())
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
/// * `prefix` — a routing prefix as returned by [`ObjectHandle::hsm_prefix`]
pub(crate) fn hsm_model_from_prefix<'a>(
    hsm_instances: &'a [HsmInstanceParams],
    prefix: &'a str,
) -> &'a str {
    hsm_instances
        .iter()
        .find(|i| i.prefix == prefix)
        .map_or(prefix, |i| i.model.as_str())
}

/// Resolve an [`ObjectHandle`] to the set of concrete object UIDs it addresses.
///
/// A `Tags` handle expands to every UID carrying all of the requested tags; any other
/// handle resolves to the single UID it wraps.
/// # Arguments
/// * `handle` - the classified request identifier
/// * `kms` - A reference to the KMS object
/// # Returns
/// * `KResult` - A `HashSet` of strings representing the possible UIDs
pub(super) async fn resolve_uids(handle: ObjectHandle<'_>, kms: &KMS) -> KResult<HashSet<String>> {
    match handle {
        ObjectHandle::Tags(json) => {
            let tags: HashSet<String> = serde_json::from_str(json)?;
            Ok(kms.database.list_uids_for_tags(&tags).await?)
        }
        handle => Ok(HashSet::from([handle.as_str().to_owned()])),
    }
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

/// Parse a version suffix string (`latest`, `first`, `0`, `N`) into a `KeysetVersion`.
/// Returns `None` if the suffix is not a valid version specifier.
fn parse_version_suffix(version_str: &str) -> Option<KeysetVersion> {
    match version_str {
        "latest" => Some(KeysetVersion::Latest),
        "first" => Some(KeysetVersion::First),
        s => s.parse::<i32>().ok().map(|n| {
            if n == 0 {
                KeysetVersion::First
            } else {
                KeysetVersion::Generation(n)
            }
        }),
    }
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
    if identifier.starts_with('[') {
        return None;
    }
    // HSM UID handling:
    // - With an `@N` generation suffix (e.g. `hsm::softhsm2::0::my-key@1`) → direct PKCS#11
    //   key handle for a specific generation; never a keyset reference.
    // - Without `@N` (plain base UID, e.g. `hsm::softhsm2::0::my-key`) → this IS the keyset
    //   name (= rotate_name = full base UID). Treat it as a bare keyset reference so that:
    //     · Encrypt / Sign (`SingleLatest`) resolves to the current latest generation.
    //     · Decrypt / Verify (`TryEach`) chain-walks through all generations newest-to-oldest.
    if identifier.starts_with("hsm::") {
        if identifier.contains('@') {
            // Explicit `@N` → direct generation handle, not a keyset ref.
            return None;
        }
        // Plain HSM base UID → bare keyset reference.
        return Some(KeysetRef {
            name: identifier.to_owned(),
            version: KeysetVersion::Bare,
        });
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

        let version = parse_version_suffix(version_str)?;

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
/// For `@latest` or `Bare` mode, resolves to the key with the highest `rotate_generation`.
/// For `@first` or `@N`, resolves to the key with the matching generation.
///
/// Returns `None` if the keyset name doesn't match any object.
pub(crate) async fn resolve_keyset_to_single_uid(
    keyset_ref: &KeysetRef,
    kms: &KMS,
    user: &UserId,
) -> KResult<Option<String>> {
    let generation = match &keyset_ref.version {
        KeysetVersion::Latest | KeysetVersion::Bare => None,
        KeysetVersion::First => Some(0),
        KeysetVersion::Generation(n) => Some(*n),
    };

    let results = kms
        .database
        .find_by_rotate_name(&keyset_ref.name, generation, user)
        .await?;

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

/// Resolve a keyset reference in a rekey operation to a concrete UID.
///
/// This combines [`ObjectHandle::as_keyset_ref`] + [`resolve_keyset_to_single_uid`] into a
/// single call with uniform error handling, suitable for use in rekey dispatchers.
///
/// # Return value
/// - `Ok(None)` — `uid` is not a keyset reference, or is a bare keyset name that has no
///   members (key exists but has no `rotate_name` set, or keyset lookup returns empty).
///   The caller should treat `uid` as a direct object identifier.
/// - `Ok(Some(resolved_uid))` — `uid` was a keyset reference and resolved successfully.
/// - `Err(...)` — `uid` used an explicit versioned keyset syntax (`@latest`, `@N`, `@first`)
///   but the keyset could not be found; this is always a user error.
pub(crate) async fn resolve_uid_or_keyset(
    handle: ObjectHandle<'_>,
    op_name: &str,
    kms: &KMS,
    user: &UserId,
) -> KResult<Option<String>> {
    let Some(keyset_ref) = as_keyset_ref(handle) else {
        return Ok(None);
    };
    let resolved = resolve_keyset_to_single_uid(&keyset_ref, kms, user).await?;
    match resolved {
        Some(resolved_uid) => Ok(Some(resolved_uid)),
        None => match &keyset_ref.version {
            // Bare name (or plain HSM base UID): no keyset members found → fall through
            // to direct object lookup. The key may simply have no rotate_name set yet.
            KeysetVersion::Bare => Ok(None),
            // Explicit versioned ref (`@latest`, `@N`, `@first`): not finding the keyset
            // is always a user error.
            _ => Err(KmsError::InvalidRequest(format!(
                "{op_name}: keyset '{handle}' not found or has no resolvable latest key"
            ))),
        },
    }
}

/// Walk the keyset rotation chain from the latest key backward.
///
/// Fetches every member of the keyset (all generations) via `find_by_rotate_name`,
/// then sorts them newest-to-oldest by `rotate_generation`.
///
/// This works identically for SQL and HSM keys:
/// - SQL keys store generation in the `RotateGeneration` JSON attribute.
/// - HSM keys store generation in `CKA_LABEL` and expose it through the same
///   `rotate_generation` field.
///
/// `ReplacedObjectLink` / `ReplacementObjectLink` back-pointers are still
/// written on each rotation for KMIP protocol compliance, but are not used
/// for chain traversal.
///
/// Returns the ordered list of UIDs to try for decryption (newest first).
pub(crate) async fn walk_keyset_chain(
    keyset_name: &str,
    kms: &KMS,
    user: &UserId,
) -> KResult<Vec<String>> {
    let results = kms
        .database
        .find_by_rotate_name(keyset_name, None, user)
        .await?;

    if results.is_empty() {
        return Ok(vec![]);
    }

    // Sort all generations newest-first.
    let mut all_pairs: Vec<(String, i32)> = results
        .into_iter()
        .map(|(uid, attrs)| (uid, attrs.rotate_generation.unwrap_or(0)))
        .collect();
    all_pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
    let chain: Vec<String> = all_pairs.into_iter().map(|(uid, _)| uid).collect();

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
        // HSM UID with @N suffix → explicit generation handle, NOT a keyset ref.
        assert!(parse_keyset_identifier("hsm::softhsm2::0::my-key@1").is_none());
        assert!(parse_keyset_identifier("hsm::softhsm2::0::my-key@2").is_none());
        assert!(parse_keyset_identifier("hsm::1667223158::vec_rk_fl@1").is_none());
    }

    #[test]
    fn test_parse_hsm_plain_base_uid_is_keyset() {
        // Plain HSM base UID (no @N) → bare keyset reference (= rotate_name).
        let r = parse_keyset_identifier("hsm::softhsm2::0::my-key").expect("should parse");
        assert_eq!(r.name, "hsm::softhsm2::0::my-key");
        assert_eq!(r.version, KeysetVersion::Bare);

        // Also works for the legacy single-segment slot format.
        let r2 = parse_keyset_identifier("hsm::1667223158::vec_rk_fl").expect("should parse");
        assert_eq!(r2.name, "hsm::1667223158::vec_rk_fl");
        assert_eq!(r2.version, KeysetVersion::Bare);
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

#[cfg(test)]
mod hsm_tests {
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
