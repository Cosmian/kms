//! Metadata object + shared `SecretData` storage primitives for the KV v2-compatible API.
//!
//! Each path has exactly one active companion `SecretData` object storing the JSON-serialized
//! [`PathMetadata`]. It lives at a UID only the server can compute ([`path_metadata_uid`]),
//! keyed by [`KMS::internal_uid_key`], and is the **sole ACL anchor** for the path: every KV
//! operation on `{path}` is authorized against this object's owner/grants (via [`authorize`]),
//! never against the version objects or against tags, which KMIP clients may set. Version
//! objects are owned by the path owner and referenced by UID from the metadata, so sharing a
//! path only requires granting an operation on the metadata object with `POST /access/grant`.
//!
//! ## ACL mapping
//!
//! There is no KV-specific permission in [`KmipOperation`]; each KV action is
//! mapped to the closest existing variant:
//! - `put`  → [`KmipOperation::Import`] (the caller supplies the raw secret value).
//! - `get`  → [`KmipOperation::Get`] (reading raw secret material).
//! - `list` → [`KmipOperation::Locate`] (discovery only, no data exposure).
//! - `delete` (soft or hard) → [`KmipOperation::Destroy`].
//!
//! `get` and `list` accept a `Get` grant as covering them, like the rest of the KMS;
//! `put` and `delete` require the exact operation, so a read-only grantee can neither
//! replace nor destroy a secret.
//!
//! ## Generations
//!
//! A hard delete destroys the metadata object but keeps its row, so a re-created path uses the
//! next generation's UID. Generations are created in order, so the latest one is found with an
//! exponential then binary search over "does this UID exist" in `O(log generations)` reads.
//!
//! ## Bounds
//!
//! A path holds at most [`MAX_KV_VERSIONS`] versions: further writes are refused until the path
//! is hard-deleted, nothing is pruned silently.

use std::collections::{BTreeMap, HashSet};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{SecretDataType, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType},
            kmip_types::KeyFormatType,
            requests::create_secret_data_kmip_object,
        },
        time_normalize,
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::warn;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::error::{KvApiError, KvResult};
use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission},
    middlewares::UserId,
};

/// Marker tag set on every KV-managed object (metadata and version objects alike).
pub(crate) const KV_MARKER_TAG: &str = "_kv";

/// Marker tag set on metadata objects only, used to list the paths visible to a caller.
pub(crate) const KV_METADATA_TAG: &str = "_kv::metadata";

/// Prefix of the keyed tag marking a live version that carries a TTL (see [`ttl_active_tag`]).
const TTL_ACTIVE_TAG_PREFIX: &str = "_kv::ttl-active::";

/// Maximum path length that keeps the longest KV tag within SQL `VARCHAR(255)`.
pub(crate) const MAX_KV_PATH_LENGTH: usize = 255 - "_kv::version::".len() - "::".len() - 20;

/// Maximum number of versions a path keeps; writes beyond it are refused, never pruned.
pub(crate) const MAX_KV_VERSIONS: usize = 1_000;

/// Generations a path may go through (hard delete + re-create) before writes are refused.
pub(crate) const MAX_KV_GENERATIONS: u64 = 1 << 20;

/// Maximum number of metadata objects a single list request examines.
pub(crate) const MAX_KV_LIST_CANDIDATES: usize = 10_000;

/// Maximum number of TTL-carrying versions one sweep examines; the rest wait for the next tick
/// and stay unreadable meanwhile, since reads enforce the expiry themselves.
pub(crate) const KV_TTL_SWEEP_BATCH: usize = 1_000;

/// Reject paths that would produce a KV tag too long for SQL backends.
pub(crate) fn validate_path_length(path: &str) -> KvResult<()> {
    if path.chars().count() > MAX_KV_PATH_LENGTH {
        return Err(KvApiError::BadRequest(format!(
            "path must not exceed {MAX_KV_PATH_LENGTH} characters"
        )));
    }
    Ok(())
}

/// Build the exact tag carrying the path of a metadata object (read back by listings).
pub(crate) fn meta_tag(path: &str) -> String {
    format!("_kv::meta::{path}")
}

/// Build the exact tag identifying version `version` of `path`.
pub(crate) fn version_tag(path: &str, version: u64) -> String {
    format!("_kv::version::{path}::{version}")
}

/// Extract `(path, version)` from a version tag (`_kv::version::{path}::{version}`).
fn parse_version_tag(tag: &str) -> Option<(&str, u64)> {
    let tag = tag.strip_prefix("_kv::version::")?;
    let (path, version_str) = tag.rsplit_once("::")?;
    Some((path, version_str.parse().ok()?))
}

/// One version of a path, as recorded in its metadata.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct VersionEntry {
    pub created_time: String,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
    /// UID of the `SecretData` object holding this version.
    pub object_uid: String,
    /// Unix time after which the version is expired and unreadable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl VersionEntry {
    /// Whether the version is soft-deleted, destroyed or expired at Unix time `now`.
    pub(crate) fn is_unavailable(&self, now: i64) -> bool {
        self.destroyed
            || !self.deletion_time.is_empty()
            || self.expires_at.is_some_and(|expiry| expiry <= now)
    }
}

/// JSON payload stored inside the metadata `SecretData` object.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PathMetadata {
    pub path: String,
    /// Generation of the path: the metadata object lives at the UID [`path_metadata_uid`]
    /// derives from the path and this generation.
    pub generation: u64,
    pub current_version: u64,
    pub oldest_version: u64,
    pub created_time: String,
    pub updated_time: String,
    pub versions: BTreeMap<u64, VersionEntry>,
}

/// Current time as RFC 3339 text and Unix seconds.
pub(crate) fn now() -> KvResult<(String, i64)> {
    let now = OffsetDateTime::now_utc();
    let text = now
        .format(&Rfc3339)
        .map_err(|e| KvApiError::InternalError(format!("failed to format timestamp: {e}")))?;
    Ok((text, now.unix_timestamp()))
}

/// HMAC-SHA256 of `message` under the server's internal UID key.
fn keyed_digest(key: &[u8], message: &str) -> KvResult<Vec<u8>> {
    let derive = || -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let pkey = PKey::hmac(key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(message.as_bytes())?;
        signer.sign_to_vec()
    };
    derive().map_err(|e| KvApiError::InternalError(format!("KV keyed digest failed: {e}")))
}

/// UID of the metadata object of generation `generation` of `path`: HMAC-SHA256 under the
/// server key, truncated to a UUID.
///
/// Concurrent first writes converge on one UID. KMIP clients can choose the UID of the objects
/// they create and may set tags, but cannot compute this UID, so they can neither occupy a
/// path's metadata UID nor pass a forged object off as its metadata.
pub(crate) fn path_metadata_uid(key: &[u8], path: &str, generation: u64) -> KvResult<String> {
    let mac = keyed_digest(key, &format!("kv-metadata-v2:{generation}:{path}"))?;
    let uid_bytes = mac
        .get(..16)
        .ok_or_else(|| KvApiError::InternalError("failed to derive KV metadata UID".into()))?;
    Uuid::from_slice(uid_bytes)
        .map(|uid| uid.to_string())
        .map_err(|e| KvApiError::InternalError(format!("failed to derive KV metadata UID: {e}")))
}

/// Tag set on every live version carrying a TTL: the TTL sweep only visits these.
///
/// It is keyed by the server key so that no client can make the sweep visit its objects.
pub(crate) fn ttl_active_tag(key: &[u8]) -> KvResult<String> {
    let mac = keyed_digest(key, "kv-ttl-active-v1")?;
    let suffix = mac
        .get(..16)
        .ok_or_else(|| KvApiError::InternalError("failed to derive the KV TTL tag".into()))?;
    Ok(format!("{TTL_ACTIVE_TAG_PREFIX}{}", hex::encode(suffix)))
}

/// Where the metadata of a path is, or where it would be created.
pub(crate) enum PathLookup {
    /// The path exists.
    Active {
        owm: Box<ObjectWithMetadata>,
        metadata: PathMetadata,
    },
    /// The path does not exist; a first write creates its metadata at `uid`.
    Free { generation: u64, uid: String },
}

/// The object stored at generation `generation` of `path`, whatever its state.
///
/// Read straight from the store: the object cache only revalidates state and `sensitive`, so a
/// metadata object replaced by a concurrent write (or by another node) could be served stale,
/// and a write that read it would lose or misreport versions.
async fn retrieve_generation(
    kms: &KMS,
    key: &[u8],
    path: &str,
    generation: u64,
) -> KvResult<Option<ObjectWithMetadata>> {
    let uid = path_metadata_uid(key, path, generation)?;
    Ok(kms.database.retrieve_object_uncached(&uid).await?)
}

/// Locate the latest generation of `path`.
///
/// # Errors
/// An active object at the latest generation that is not this path's metadata is an internal
/// error: only the server can create objects at these UIDs.
pub(crate) async fn lookup_path(kms: &KMS, path: &str) -> KvResult<PathLookup> {
    let key = kms.internal_uid_key().await?;
    let Some(mut latest) = retrieve_generation(kms, key, path, 0).await? else {
        return Ok(PathLookup::Free {
            generation: 0,
            uid: path_metadata_uid(key, path, 0)?,
        });
    };
    // `low` exists and `high` does not; generation `MAX_KV_GENERATIONS` never exists.
    let mut low = 0_u64;
    let mut step = 1_u64;
    let mut high = loop {
        let probe = low.saturating_add(step).min(MAX_KV_GENERATIONS);
        if probe == MAX_KV_GENERATIONS {
            break probe;
        }
        match retrieve_generation(kms, key, path, probe).await? {
            Some(owm) => {
                low = probe;
                latest = owm;
                step = step.saturating_mul(2);
            }
            None => break probe,
        }
    };
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        match retrieve_generation(kms, key, path, mid).await? {
            Some(owm) => {
                low = mid;
                latest = owm;
            }
            None => high = mid,
        }
    }
    if matches!(
        latest.state(),
        State::Destroyed | State::Destroyed_Compromised
    ) {
        return Ok(PathLookup::Free {
            generation: high,
            uid: path_metadata_uid(key, path, high)?,
        });
    }
    let metadata = parse_path_metadata(&latest)
        .filter(|metadata| metadata.path == path && metadata.generation == low)
        .ok_or_else(|| {
            KvApiError::InternalError(format!(
                "object {} is not the KV metadata it should be",
                latest.id()
            ))
        })?;
    Ok(PathLookup::Active {
        owm: Box::new(latest),
        metadata,
    })
}

/// The metadata of `path` if it exists.
pub(crate) async fn find_metadata(
    kms: &KMS,
    path: &str,
) -> KvResult<Option<(ObjectWithMetadata, PathMetadata)>> {
    Ok(match lookup_path(kms, path).await? {
        PathLookup::Active { owm, metadata } => Some((*owm, metadata)),
        PathLookup::Free { .. } => None,
    })
}

/// Decode `owm` as KV metadata; `None` when it holds anything else.
fn parse_path_metadata(owm: &ObjectWithMetadata) -> Option<PathMetadata> {
    serde_json::from_slice(secret_bytes(owm).ok()?).ok()
}

/// Build a `SecretData` object holding opaque `bytes`, tagged with `tags`.
fn build_secret_object(vendor_id: &str, bytes: &[u8], tags: &HashSet<String>) -> KvResult<Object> {
    let mut attrs = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Attributes::default()
    };
    attrs
        .set_tags(vendor_id, tags)
        .map_err(|e| KvApiError::InternalError(format!("failed to set KV tags: {e}")))?;
    create_secret_data_kmip_object(vendor_id, bytes, SecretDataType::Password, &attrs)
        .map_err(|e| KvApiError::InternalError(format!("failed to build SecretData object: {e}")))
}

/// `extra_tags` plus [`KV_MARKER_TAG`].
fn kv_tags(extra_tags: &[String]) -> HashSet<String> {
    extra_tags
        .iter()
        .cloned()
        .chain([KV_MARKER_TAG.to_owned()])
        .collect()
}

/// Persist a brand-new KV-managed `SecretData` object (metadata or version), owned by `owner`.
pub(crate) fn create_object_operation(
    kms: &KMS,
    uid: &str,
    owner: &UserId,
    bytes: &[u8],
    extra_tags: &[String],
) -> KvResult<AtomicOperation> {
    let tags = kv_tags(extra_tags);
    let object = build_secret_object(kms.vendor_id(), bytes, &tags)?;
    let attributes = object
        .attributes()
        .map_err(|e| KvApiError::InternalError(format!("failed to read attributes: {e}")))?
        .clone();
    Ok(AtomicOperation::Create((
        uid.to_owned(),
        owner.clone(),
        object,
        attributes,
        tags,
    )))
}

/// Persist a brand-new KV-managed `SecretData` object, owned by `owner`.
#[cfg(test)]
pub(crate) async fn create_object(
    kms: &KMS,
    uid: &str,
    owner: &UserId,
    bytes: &[u8],
    extra_tags: &[String],
) -> KvResult<()> {
    let operation = create_object_operation(kms, uid, owner, bytes, extra_tags)?;
    kms.database.atomic(owner, &[operation]).await?;
    Ok(())
}

/// The store version of `owm`, required for every compare-and-swap.
fn stored_version(owm: &ObjectWithMetadata) -> KvResult<u64> {
    owm.version().ok_or_else(|| {
        KvApiError::InternalError(format!("object {} has no store version", owm.id()))
    })
}

/// Extract the raw opaque bytes stored in a KV `SecretData` object, without copying them.
pub(crate) fn secret_bytes(owm: &ObjectWithMetadata) -> KvResult<&[u8]> {
    let Object::SecretData(sd) = owm.object() else {
        return Err(KvApiError::InternalError(
            "KV object is not a SecretData object".to_owned(),
        ));
    };
    sd.key_block
        .key_bytes_ref()
        .map_err(|e| KvApiError::InternalError(format!("failed to read KV secret bytes: {e}")))
}

/// Require that `user` holds `op` on the path's metadata object.
///
/// Reads (`Get`, `Locate`) accept a `Get` grant as a read-everything grant, like the rest of
/// the KMS. Writes (`Import`) and deletes (`Destroy`) require that exact operation: a
/// read-only grantee must not be able to replace or destroy a secret.
pub(crate) async fn authorize(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    op: KmipOperation,
) -> KvResult<()> {
    let allowed = match op {
        KmipOperation::Get | KmipOperation::Locate => {
            user_has_permission(user, Some(owm), &op, kms).await
        }
        _ => kms.user_can_perform_operation(owm, user, &op).await,
    }?;
    if allowed {
        Ok(())
    } else {
        Err(KvApiError::Forbidden)
    }
}

/// Build the compare-and-swap replacing the metadata stored in `owm` by `metadata`.
///
/// It fails (conflict) if the metadata changed or was destroyed since `owm` was read.
pub(crate) fn metadata_update_operation(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    metadata: &PathMetadata,
) -> KvResult<AtomicOperation> {
    let bytes = serde_json::to_vec(metadata)
        .map_err(|e| KvApiError::InternalError(format!("failed to serialize KV metadata: {e}")))?;
    let tags = kv_tags(&metadata_tags(&metadata.path));
    let object = build_secret_object(kms.vendor_id(), &bytes, &tags)?;
    let attributes = object
        .attributes()
        .map_err(|e| KvApiError::InternalError(format!("failed to read attributes: {e}")))?
        .clone();
    Ok(AtomicOperation::CompareAndSwapObject {
        uid: owm.id().to_owned(),
        expected_version: stored_version(owm)?,
        object: Box::new(object),
        attributes,
        tags: Some(tags),
    })
}

/// Tags of a metadata object, besides [`KV_MARKER_TAG`].
pub(crate) fn metadata_tags(path: &str) -> [String; 2] {
    [meta_tag(path), KV_METADATA_TAG.to_owned()]
}

/// Persist `metadata` without changing the object's lifecycle state.
pub(crate) async fn save_metadata(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    metadata: &PathMetadata,
) -> KvResult<()> {
    let operation = metadata_update_operation(kms, owm, metadata)?;
    kms.database.atomic(owm.owner_id(), &[operation]).await?;
    Ok(())
}

/// Build the operations destroying a version object the way KMIP `Destroy` does: the
/// secret bytes are wiped (not only the state changed), so a destroyed secret cannot be
/// read back from the database, and the version leaves the TTL sweep's candidates.
pub(crate) fn destroy_version_operations(
    vendor_id: &str,
    owm: &ObjectWithMetadata,
) -> KvResult<[AtomicOperation; 2]> {
    let mut tags = owm.attributes().get_tags(vendor_id);
    tags.retain(|tag| !tag.starts_with(TTL_ACTIVE_TAG_PREFIX));
    let mut attributes = owm.attributes().clone();
    attributes
        .set_tags(vendor_id, &tags)
        .map_err(|e| KvApiError::InternalError(format!("failed to set KV tags: {e}")))?;
    attributes.state = Some(State::Destroyed);
    attributes.destroy_date = Some(
        time_normalize()
            .map_err(|e| KvApiError::InternalError(format!("failed to read the time: {e}")))?,
    );
    let mut object = owm.object().clone();
    let key_block = object
        .key_block_mut()
        .map_err(|e| KvApiError::InternalError(format!("KV object has no key block: {e}")))?;
    key_block.key_format_type = KeyFormatType::Raw;
    key_block.key_value = Some(KeyValue::Structure {
        key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
        attributes: Some(Box::new(attributes.clone())),
    });
    Ok([
        AtomicOperation::CompareAndSwapObject {
            uid: owm.id().to_owned(),
            expected_version: stored_version(owm)?,
            object: Box::new(object),
            attributes,
            tags: Some(tags),
        },
        AtomicOperation::UpdateState((owm.id().to_owned(), State::Destroyed)),
    ])
}

/// Destroy every live version whose TTL has elapsed, marking it destroyed in its metadata.
///
/// Called periodically by [`crate::cron::spawn_kv_ttl_cron`]; reads already refuse expired
/// versions, so the sweep only reclaims their bytes. Returns the number of versions destroyed.
///
/// # Errors
/// Fails when the candidates cannot be listed, or with the first per-version failure once every
/// candidate has been tried; each failure is logged with the object UID.
pub(crate) async fn sweep_expired_versions(kms: &KMS) -> KvResult<usize> {
    sweep_expired_versions_at(kms, OffsetDateTime::now_utc().unix_timestamp()).await
}

/// [`sweep_expired_versions`] with an explicit current Unix time.
pub(crate) async fn sweep_expired_versions_at(kms: &KMS, now: i64) -> KvResult<usize> {
    let tag = ttl_active_tag(kms.internal_uid_key().await?)?;
    let candidates = kms
        .database
        .list_uids_for_tags(&HashSet::from([tag]))
        .await?;
    let mut destroyed = 0_usize;
    let mut first_error = None;
    for uid in candidates.into_iter().take(KV_TTL_SWEEP_BATCH) {
        match Box::pin(expire_version(kms, &uid, now)).await {
            Ok(true) => destroyed += 1,
            Ok(false) => {}
            Err(error) => {
                warn!("[kv-ttl-cron] cannot expire KV version object {uid}: {error}");
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(destroyed), Err)
}

/// Destroy the TTL candidate `uid` if its metadata says it has expired at `now`.
async fn expire_version(kms: &KMS, uid: &str, now: i64) -> KvResult<bool> {
    let Some(owm) = kms.database.retrieve_object(uid).await? else {
        return Ok(false);
    };
    // Destroyed outside KV (KMIP `Destroy`): nothing left to reclaim.
    if matches!(owm.state(), State::Destroyed | State::Destroyed_Compromised) {
        return Ok(false);
    }
    let tags = owm.attributes().get_tags(kms.vendor_id());
    let (path, version) = tags
        .iter()
        .find_map(|tag| parse_version_tag(tag))
        .ok_or_else(|| KvApiError::InternalError("TTL candidate has no version tag".to_owned()))?;
    let PathLookup::Active {
        owm: meta_owm,
        mut metadata,
    } = lookup_path(kms, path).await?
    else {
        return Err(KvApiError::InternalError(
            "TTL candidate belongs to no live path".to_owned(),
        ));
    };
    let entry = metadata
        .versions
        .get_mut(&version)
        .filter(|entry| entry.object_uid == uid && owm.owner() == meta_owm.owner())
        .ok_or_else(|| {
            KvApiError::InternalError("TTL candidate is not recorded by its path".to_owned())
        })?;
    if entry.expires_at.is_none_or(|expiry| expiry > now) {
        return Ok(false);
    }
    entry.destroyed = true;
    if entry.deletion_time.is_empty() {
        entry.deletion_time = OffsetDateTime::from_unix_timestamp(now)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .ok_or_else(|| KvApiError::InternalError("invalid sweep time".to_owned()))?;
    }
    let [wipe, mark_destroyed] = destroy_version_operations(kms.vendor_id(), &owm)?;
    let operations = [
        metadata_update_operation(kms, &meta_owm, &metadata)?,
        wipe,
        mark_destroyed,
    ];
    kms.database
        .atomic(meta_owm.owner_id(), &operations)
        .await?;
    Ok(true)
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use super::*;

    #[test]
    fn metadata_and_version_tags_have_disjoint_namespaces() {
        assert_ne!(meta_tag("1"), version_tag("meta", 1));
        assert!(!KV_METADATA_TAG.starts_with(&meta_tag("")));
    }

    #[test]
    fn path_length_fits_the_longest_version_tag() -> Result<(), KvApiError> {
        let valid_path = "a".repeat(MAX_KV_PATH_LENGTH);
        let too_long_path = format!("{valid_path}a");
        validate_path_length(&valid_path)?;
        assert!(matches!(
            validate_path_length(&too_long_path),
            Err(KvApiError::BadRequest(_))
        ));
        assert_eq!(version_tag(&valid_path, u64::MAX).chars().count(), 255);
        Ok(())
    }

    #[test]
    fn keyed_identifiers_are_stable_and_unpredictable() -> Result<(), KvApiError> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let key = [7_u8; 32];
        let other_key = [8_u8; 32];
        assert_eq!(
            path_metadata_uid(&key, "myapp/key", 0)?,
            path_metadata_uid(&key, "myapp/key", 0)?
        );
        assert_ne!(
            path_metadata_uid(&key, "myapp/key", 0)?,
            path_metadata_uid(&key, "myapp/other", 0)?
        );
        assert_ne!(
            path_metadata_uid(&key, "myapp/key", 0)?,
            path_metadata_uid(&key, "myapp/key", 1)?
        );
        // Without the server key, neither the UID nor the TTL tag can be predicted.
        assert_ne!(
            path_metadata_uid(&key, "myapp/key", 0)?,
            path_metadata_uid(&other_key, "myapp/key", 0)?
        );
        assert_ne!(ttl_active_tag(&key)?, ttl_active_tag(&other_key)?);
        assert!(ttl_active_tag(&key)?.starts_with(TTL_ACTIVE_TAG_PREFIX));
        Ok(())
    }

    /// Metadata written without a version object UID is not KV metadata: there is no legacy
    /// tag-based fallback to resolve it.
    #[test]
    fn metadata_without_object_uid_is_rejected() {
        let legacy = r#"{"path":"p","generation":0,"current_version":1,"oldest_version":1,"created_time":"now","updated_time":"now","versions":{"1":{"created_time":"now","deletion_time":"","destroyed":false}}}"#;
        assert!(serde_json::from_str::<PathMetadata>(legacy).is_err());
        let current = legacy.replace(
            r#""destroyed":false"#,
            r#""destroyed":false,"object_uid":"u""#,
        );
        let metadata: PathMetadata =
            serde_json::from_str(&current).expect("metadata with object_uid parses");
        assert_eq!(metadata.versions[&1].object_uid, "u");
    }

    #[test]
    fn version_availability_honours_expiry_deletion_and_destruction() {
        let entry = VersionEntry {
            created_time: String::new(),
            deletion_time: String::new(),
            destroyed: false,
            object_uid: "u".to_owned(),
            expires_at: Some(100),
        };
        assert!(!entry.is_unavailable(99));
        assert!(entry.is_unavailable(100));
        assert!(
            VersionEntry {
                expires_at: None,
                destroyed: true,
                ..entry.clone()
            }
            .is_unavailable(0)
        );
        assert!(
            VersionEntry {
                expires_at: None,
                deletion_time: "t".to_owned(),
                ..entry
            }
            .is_unavailable(0)
        );
    }

    #[test]
    fn parse_version_tag_requires_version_namespace() {
        assert_eq!(
            parse_version_tag("_kv::version::myapp::nested::3"),
            Some(("myapp::nested", 3))
        );
        assert_eq!(parse_version_tag("_kv::meta::1"), None);
        assert_eq!(parse_version_tag("_kv::version::myapp::invalid"), None);
    }
}
