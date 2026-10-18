//! Metadata object + shared `SecretData` storage primitives for the KV v2-compatible API.
//!
//! Each path has exactly one companion `SecretData` object, tagged
//! [`meta_tag`], storing the JSON-serialized [`PathMetadata`]. This object is
//! the **sole ACL anchor** for the path: every KV operation on `{path}` is
//! authorized against this object's owner/grants (via [`authorize`]), never
//! against the individual version objects. Version objects are always owned
//! by the path's original creator (the metadata object's owner), so sharing a
//! path only requires granting an operation on the metadata object — matching
//! the "owner + `_kv::{path}` tag grants" ACL model from issue #863, reusing
//! the existing `POST /access/grant` endpoint (no new grant plumbing).
//!
//! ## ACL mapping
//!
//! There is no KV-specific permission in [`KmipOperation`]; each KV action is
//! mapped to the closest existing variant:
//! - `put`  → [`KmipOperation::Import`] (the caller supplies the raw secret
//!   value, mirroring the existing `Import` path for `SecretData` objects).
//! - `get`  → [`KmipOperation::Get`] (reading raw secret material).
//! - `list` → [`KmipOperation::Locate`] (discovery only, no data exposure).
//! - `delete` (soft or hard) → [`KmipOperation::Destroy`] (one permission
//!   governs every delete variant for simplicity).
//!
//! ## Version history
//!
//! All versions are kept indefinitely (no Vault-style `max_versions`
//! pruning) — a deliberate v1 scope decision; add pruning later if operators
//! need it.

use std::collections::HashMap;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{SecretDataType, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
            requests::create_secret_data_kmip_object,
        },
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::error::{KvApiError, KvResult};
use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission},
    middlewares::UserId,
};

/// Marker tag set on every KV-managed object (metadata and version objects
/// alike), used for the `LIST` prefix scan and the TTL cron sweep.
pub(crate) const KV_MARKER_TAG: &str = "_kv";

/// Build the exact tag identifying the metadata object for `path`.
pub(crate) fn meta_tag(path: &str) -> String {
    format!("_kv::meta::{path}")
}

/// Build the exact tag identifying version `version` of `path`.
pub(crate) fn version_tag(path: &str, version: u64) -> String {
    format!("_kv::{path}::{version}")
}

/// Build the tag recording a version's absolute TTL expiry (Unix seconds).
pub(crate) fn ttl_tag(unix_ts: i64) -> String {
    format!("_kv::ttl::{unix_ts}")
}

/// Parse a `_kv::ttl::{unix_ts}` tag, if present, returning the timestamp.
pub(crate) fn parse_ttl_tag(tag: &str) -> Option<i64> {
    tag.strip_prefix("_kv::ttl::")?.parse().ok()
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct VersionEntry {
    pub created_time: String,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
}

/// JSON payload stored inside the metadata `SecretData` object.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct PathMetadata {
    pub path: String,
    pub current_version: u64,
    pub oldest_version: u64,
    pub created_time: String,
    pub updated_time: String,
    pub versions: HashMap<String, VersionEntry>,
}

pub(crate) fn now_rfc3339() -> KvResult<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| KvApiError::InternalError(format!("failed to format timestamp: {e}")))
}

/// Build a `SecretData` object holding opaque `bytes`, tagged with
/// [`KV_MARKER_TAG`] plus every tag in `extra_tags`.
fn build_secret_object(vendor_id: &str, bytes: &[u8], extra_tags: &[String]) -> KvResult<Object> {
    let mut attrs = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Attributes::default()
    };
    let mut tags: Vec<String> = extra_tags.to_vec();
    tags.push(KV_MARKER_TAG.to_owned());
    attrs
        .set_tags(vendor_id, tags)
        .map_err(|e| KvApiError::InternalError(format!("failed to set KV tags: {e}")))?;
    create_secret_data_kmip_object(vendor_id, bytes, SecretDataType::Password, &attrs)
        .map_err(|e| KvApiError::InternalError(format!("failed to build SecretData object: {e}")))
}

/// Persist a brand-new KV-managed `SecretData` object (metadata or version),
/// owned by `owner`.
pub(crate) async fn create_object(
    kms: &KMS,
    uid: &str,
    owner: &UserId,
    bytes: &[u8],
    extra_tags: &[String],
) -> KvResult<()> {
    let object = build_secret_object(kms.vendor_id(), bytes, extra_tags)?;
    let attributes = object
        .attributes()
        .map_err(|e| KvApiError::InternalError(format!("failed to read attributes: {e}")))?
        .clone();
    let mut tags: std::collections::HashSet<String> = extra_tags.iter().cloned().collect();
    tags.insert(KV_MARKER_TAG.to_owned());
    kms.database
        .atomic(
            owner,
            &[AtomicOperation::Create((
                uid.to_owned(),
                owner.clone(),
                object,
                attributes,
                tags,
            ))],
        )
        .await
        .map_err(|e| KvApiError::InternalError(format!("failed to persist KV object: {e}")))?;
    Ok(())
}

/// Overwrite an existing KV-managed `SecretData` object's content in place
/// (used to update the metadata object after a new version is written, or
/// to mark it after a delete). `owner` must match the object's current owner
/// — the store rejects an `Upsert` whose owner does not match (affected-row
/// check), it is not a no-op placeholder.
pub(crate) async fn upsert_object(
    kms: &KMS,
    uid: &str,
    owner: &UserId,
    bytes: &[u8],
    extra_tags: &[String],
) -> KvResult<()> {
    let object = build_secret_object(kms.vendor_id(), bytes, extra_tags)?;
    let attributes = object
        .attributes()
        .map_err(|e| KvApiError::InternalError(format!("failed to read attributes: {e}")))?
        .clone();
    let mut tags: std::collections::HashSet<String> = extra_tags.iter().cloned().collect();
    tags.insert(KV_MARKER_TAG.to_owned());
    kms.database
        .atomic(
            owner,
            &[AtomicOperation::Upsert((
                uid.to_owned(),
                object,
                attributes,
                Some(tags),
                State::Active,
            ))],
        )
        .await
        .map_err(|e| KvApiError::InternalError(format!("failed to update KV object: {e}")))?;
    Ok(())
}

/// Extract the raw opaque bytes stored in a KV `SecretData` object.
pub(crate) fn secret_bytes(owm: &ObjectWithMetadata) -> KvResult<Vec<u8>> {
    let Object::SecretData(sd) = owm.object() else {
        return Err(KvApiError::InternalError(
            "KV object is not a SecretData object".to_owned(),
        ));
    };
    sd.key_block
        .key_bytes()
        .map(|z| z.to_vec())
        .map_err(|e| KvApiError::InternalError(format!("failed to read KV secret bytes: {e}")))
}

/// Find the metadata object for `path`, regardless of who owns it — the
/// lookup itself must not be ownership-scoped so that [`authorize`] can tell
/// "object exists but caller lacks a grant" (403) apart from "object does not
/// exist" (404), exactly like `routes::spire::pki::authorize_ca_use`.
pub(crate) async fn find_metadata(
    kms: &KMS,
    path: &str,
) -> KvResult<Option<(String, ObjectWithMetadata, PathMetadata)>> {
    let tag = meta_tag(path);
    let mut uids: Vec<String> = kms
        .database
        .list_uids_for_tags(&std::collections::HashSet::from([tag]))
        .await
        .map_err(|e| KvApiError::InternalError(format!("KV metadata lookup failed: {e}")))?
        .into_iter()
        .collect();
    uids.sort();
    let Some(uid) = uids.into_iter().next() else {
        return Ok(None);
    };
    let owm = kms
        .database
        .retrieve_object(&uid)
        .await
        .map_err(|e| KvApiError::InternalError(e.to_string()))?
        .ok_or_else(|| {
            KvApiError::InternalError(format!("KV metadata tag indexed a missing object {uid}"))
        })?;
    // A hard-deleted path's metadata object is marked `Destroyed` in place
    // (see `hard_delete_path`) rather than removed from the tag index, so it
    // must be treated as absent here.
    if owm.state() == State::Destroyed {
        return Ok(None);
    }
    let bytes = secret_bytes(&owm)?;
    let metadata: PathMetadata = serde_json::from_slice(&bytes)
        .map_err(|e| KvApiError::InternalError(format!("corrupt KV metadata for {path}: {e}")))?;
    Ok(Some((uid, owm, metadata)))
}

/// Require that `user` holds `op` on the path's metadata object (owner bypass
/// or an explicit grant — see [`user_has_permission`]).
pub(crate) async fn authorize(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    op: KmipOperation,
) -> KvResult<()> {
    let allowed = user_has_permission(user, Some(owm), &op, kms)
        .await
        .map_err(KvApiError::from)?;
    if allowed {
        return Ok(());
    }
    Err(KvApiError::Forbidden(format!(
        "identity '{user}' is not authorized to '{op}' on this KV path: grant it the \
         corresponding access right on the path's metadata object"
    )))
}

/// Persist `metadata` back to its `SecretData` object. `owner` must be the
/// metadata object's real owner (see [`upsert_object`]).
pub(crate) async fn save_metadata(
    kms: &KMS,
    uid: &str,
    owner: &UserId,
    path: &str,
    metadata: &PathMetadata,
) -> KvResult<()> {
    let bytes = serde_json::to_vec(metadata)
        .map_err(|e| KvApiError::InternalError(format!("failed to serialize KV metadata: {e}")))?;
    upsert_object(kms, uid, owner, &bytes, &[meta_tag(path)]).await
}

/// Extract `(path, version)` from a version tag (`_kv::{path}::{version}`),
/// rejecting the marker, meta, and ttl tags which share the same `_kv::` prefix.
fn parse_version_tag(tag: &str) -> Option<(&str, u64)> {
    if tag == KV_MARKER_TAG || tag.starts_with("_kv::meta::") || tag.starts_with("_kv::ttl::") {
        return None;
    }
    let (path, version_str) = tag.strip_prefix("_kv::")?.rsplit_once("::")?;
    Some((path, version_str.parse().ok()?))
}

/// Scan every KV-managed object for an elapsed TTL tag and destroy it,
/// marking the corresponding entry in its path's metadata.
///
/// Called periodically by [`crate::cron::spawn_kv_ttl_cron`] (issue #863
/// acceptance criterion: a secret written with `options.ttl = "5m"` is
/// automatically deleted after 5 minutes). Returns the number of versions
/// destroyed.
pub(crate) async fn sweep_expired_versions(kms: &KMS) -> usize {
    let uids = match kms
        .database
        .list_uids_for_tags(&std::collections::HashSet::from([KV_MARKER_TAG.to_owned()]))
        .await
    {
        Ok(uids) => uids,
        Err(e) => {
            cosmian_logger::warn!("[kv-ttl-cron] failed to list KV objects: {e}");
            return 0;
        }
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut destroyed_count = 0_usize;

    for uid in uids {
        let Ok(Some(owm)) = kms.database.retrieve_object(&uid).await else {
            continue;
        };
        let Ok(attrs) = owm.object().attributes() else {
            continue;
        };
        let tags = attrs.get_tags(kms.vendor_id());

        let Some(expiry) = tags.iter().find_map(|t| parse_ttl_tag(t)) else {
            continue;
        };
        if expiry > now {
            continue;
        }
        let Some((path, version)) = tags.iter().find_map(|t| parse_version_tag(t)) else {
            continue;
        };

        if kms
            .database
            .update_state(&uid, State::Destroyed)
            .await
            .is_err()
        {
            continue;
        }
        destroyed_count += 1;

        let Ok(Some((meta_uid, meta_owm, mut path_metadata))) = find_metadata(kms, path).await
        else {
            continue;
        };
        if let Some(entry) = path_metadata.versions.get_mut(&version.to_string()) {
            entry.destroyed = true;
            if entry.deletion_time.is_empty() {
                entry.deletion_time = now_rfc3339().unwrap_or_default();
            }
        }
        if let Err(e) =
            save_metadata(kms, &meta_uid, meta_owm.owner_id(), path, &path_metadata).await
        {
            cosmian_logger::warn!(
                "[kv-ttl-cron] destroyed version {version} of '{path}' but failed to update \
                 its metadata: {e}"
            );
        }
    }
    destroyed_count
}
