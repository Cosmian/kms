//! HSM-resident symmetric key rotation via PKCS#11.
//!
//! This module handles `ReKey` for keys whose UID starts with `hsm::` — non-extractable
//! key material managed by a hardware token.  The rotation algorithm generates a new key
//! on the same HSM slot (via `C_GenerateKey`), assigns a generation-suffixed UID, and
//! updates `CKA_LABEL` / `CKA_START_DATE` / `CKA_END_DATE` on both old and new keys.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation, kmip_objects::ObjectType, kmip_operations::ReKeyResponse,
        kmip_types::UniqueIdentifier,
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::trace;
use time::OffsetDateTime;

use crate::{
    core::{KMS, uid_utils::has_prefix},
    error::KmsError,
    result::KResult,
};

impl KMS {
    /// Find the latest generation UID in a keyset identified by `rotate_name`.
    pub(super) async fn latest_hsm_keyset_uid(
        &self,
        rotate_name: &str,
        user: &str,
    ) -> Option<String> {
        self.database
            .find_by_rotate_name(rotate_name, None, user)
            .await
            .ok()
            .and_then(|keys| {
                keys.into_iter()
                    .max_by_key(|(_, attrs)| attrs.rotate_generation.unwrap_or(0))
                    .map(|(uid, _)| uid)
            })
    }

    /// Rotate an HSM-resident AES symmetric key.
    ///
    /// ## Rotation algorithm
    ///
    /// 1. Validate that the caller has `Rekey` permission.
    /// 2. Retrieve the old key's metadata from the HSM (algorithm, length, sensitivity,
    ///    keyset info from `CKA_LABEL`, rotation interval from `CKA_START_DATE`/`CKA_END_DATE`).
    /// 3. Compute the new generation number and new `key_id`/UID
    ///    (`base_key_id::new_gen`, `prefix::slot::base_key_id::new_gen`).
    /// 4. Generate the new key on the same HSM slot via `C_GenerateKey` (`create_key`).
    /// 5. Infer the rotation interval from the old key's dates; stamp new `CKA_START_DATE` /
    ///    `CKA_END_DATE` on the new key if an interval is known.
    /// 6. Update `CKA_LABEL` on the old key (strip `@latest` suffix) and on the new key
    ///    (append `@latest`).
    ///
    /// ## Non-latest generation rejection
    ///
    /// If the key belongs to a named keyset but is not the latest generation, the request
    /// is rejected with an error.  Callers should use the bare keyset name (e.g.
    /// `re-key --key-id my-key`) or `my-key@latest` — the dispatcher resolves those to
    /// the latest UID before this function is called.
    pub(super) async fn rekey_hsm_symmetric(
        &self,
        uid: &str,
        user: &str,
    ) -> KResult<ReKeyResponse> {
        self.enforce_create_permission(user).await?;

        // Parse the UID early — prefix, slot_id, and key_id are needed for the
        // keyset-name fallback resolution that follows.
        let prefix = has_prefix(uid)
            .ok_or_else(|| KmsError::InvalidRequest(format!("UID '{uid}' is not an HSM UID")))?;
        let rest = uid
            .strip_prefix(&format!("{prefix}::"))
            .ok_or_else(|| KmsError::InvalidRequest("HSM UID has unexpected format".to_owned()))?;
        let (slot_str, key_id) = rest.split_once("::").ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "HSM UID '{uid}' must have format '{prefix}::<slot>::<key_id>'"
            ))
        })?;
        let slot_id: usize = slot_str.parse().map_err(|e| {
            KmsError::InvalidRequest(format!("HSM slot_id '{slot_str}' is not valid: {e}"))
        })?;
        // `base_id` strips any `@N` generation suffix.
        // `has_explicit_gen` is true when the caller specified an explicit generation
        // (e.g. `hsm::slot::uuid@1`) as opposed to the stable base handle (`hsm::slot::uuid`).
        let (base_id, old_gen, has_explicit_gen) = key_id
            .rsplit_once('@')
            .and_then(|(base, suffix)| suffix.parse::<i32>().ok().map(|n| (base, n, true)))
            .unwrap_or((key_id, 0, false));

        // Retrieve old key metadata from the HSM.
        // When the PKCS#11 slot does not have a key with this exact UID — returned
        // either as `Ok(None)` or as an `Err` containing "not found" — fall back to
        // keyset-name resolution using the full base UID as the rotate_name.
        let full_base_uid = format!("{prefix}::{slot_str}::{base_id}");
        let old_owm = match self.database.retrieve_object(uid).await {
            Ok(Some(owm)) => owm,
            Ok(None) => {
                return if let Some(latest) = self.latest_hsm_keyset_uid(&full_base_uid, user).await
                {
                    Box::pin(self.rekey_hsm_symmetric(&latest, user)).await
                } else {
                    Err(KmsError::InvalidRequest(format!(
                        "HSM key '{uid}' not found and no keyset named '{full_base_uid}' exists on \
                         this HSM slot"
                    )))
                };
            }
            Err(e) => {
                // PKCS#11 returns an error (not just empty results) for missing objects;
                // treat any "not found" message as an absent key and try keyset resolution.
                if e.to_string().to_lowercase().contains("not found") {
                    return if let Some(latest) =
                        self.latest_hsm_keyset_uid(&full_base_uid, user).await
                    {
                        Box::pin(self.rekey_hsm_symmetric(&latest, user)).await
                    } else {
                        Err(KmsError::InvalidRequest(format!(
                            "HSM key '{uid}' not found and no keyset named '{full_base_uid}' exists \
                             on this HSM slot"
                        )))
                    };
                }
                return Err(KmsError::Database(e));
            }
        };

        if old_owm.object().object_type() != ObjectType::SymmetricKey {
            return Err(KmsError::NotSupported(
                "HSM ReKey is currently supported for AES symmetric keys only".to_owned(),
            ));
        }

        // Per-object authorization: the caller must own the key or hold an explicit
        // Rekey grant.  `enforce_create_permission` above only checks the server-level
        // "can create" right; it does not verify ownership of this specific object.
        if !self
            .user_can_perform_operation(&old_owm, user, &KmipOperation::Rekey)
            .await?
        {
            return Err(KmsError::Unauthorized(format!(
                "User '{user}' does not have Rekey permission on HSM key '{uid}'"
            )));
        }

        let old_attrs = old_owm.attributes();

        // Decide how to handle a non-latest key:
        // - Explicit generation (@N suffix): the caller targeted a specific old generation
        //   — this is an error.  Use the base UID (no suffix) to always rotate the head.
        // - Bare base UID (no @N): treat as a stable keyset handle and redirect silently
        //   to the actual latest.  For HSM keys rotate_name is the full base UID, which
        //   is unique across slots (embed slot ID).
        if !self.is_keyset_latest(uid, old_attrs, user).await? {
            if has_explicit_gen {
                return Err(KmsError::InvalidRequest(format!(
                    "ReKey: HSM key '{uid}' is not the latest in its keyset — only the latest \
                     generation can be rotated. Use '{full_base_uid}' to always rotate the \
                     current head."
                )));
            }
            // Stable handle: redirect to the latest generation.
            // rotate_name is the full base UID (unique across slots); fall back to
            // full_base_uid for keys whose rotation policy has not been initialised.
            let keyset_id = old_attrs.rotate_name.as_deref().unwrap_or(&full_base_uid);
            if let Some(latest_uid) = self.latest_hsm_keyset_uid(keyset_id, user).await {
                if latest_uid != uid {
                    return Box::pin(self.rekey_hsm_symmetric(&latest_uid, user)).await;
                }
            }
        }

        let new_gen = old_gen + 1;
        let new_key_id = format!("{base_id}@{new_gen}");
        let new_uid = format!("{prefix}::{slot_id}::{new_key_id}");

        // Retrieve old rotate metadata from the HSM (via stub attributes).
        // Fall back gracefully if CKA_LABEL metadata is absent.
        let (rotate_name, old_rotate_gen) = (
            old_attrs.rotate_name.clone(),
            old_attrs.rotate_generation.unwrap_or(old_gen),
        );

        // Read rotation interval in days from the old key's attributes.
        // For HSM keys, rotate_interval is not stored in PKCS#11 as a KMIP attribute
        // (HsmStore::update_object is a no-op); instead it is reconstructed at
        // retrieve-time from CKA_START_DATE / CKA_END_DATE as (end − start) × 86400 s.
        // If unavailable (key was never armed with SetAttribute RotateInterval),
        // interval_days is None and the new key will not be auto-scheduled.
        let interval_days: Option<i64> = old_attrs.rotate_interval.filter(|&i| i > 0).map(|secs| {
            secs / cosmian_kms_server_database::reexport::cosmian_kms_interfaces::SECS_PER_DAY
        });

        // Generate the new key on the same HSM slot.
        if let Err(e) = self
            .database
            .create(
                Some(new_uid.clone()),
                user,
                &old_owm.object().clone(),
                old_attrs,
                &std::collections::HashSet::new(),
            )
            .await
        {
            if e.to_string().contains("already exists") {
                let latest_uid = if let Some(ref name) = rotate_name {
                    self.latest_hsm_keyset_uid(name, user).await
                } else {
                    None
                };
                let retry_hint = latest_uid.map_or_else(
                    || {
                        format!(
                            " Locate the highest-generation key on this slot \
                             (UIDs matching `{prefix}::{slot_id}::{base_id}@N`) and re-key that \
                             one."
                        )
                    },
                    |uid| {
                        format!(
                            " Re-key the current latest key instead (use the KMS client of your \
                             choice with key-id `{uid}`)."
                        )
                    },
                );
                return Err(KmsError::InvalidRequest(format!(
                    "HSM key '{new_uid}' already exists — generation {new_gen} was already \
                     created on this HSM slot. A previous rotation may have \
                     completed.{retry_hint}"
                )));
            }
            return Err(KmsError::InvalidRequest(format!(
                "Failed to generate new HSM key '{new_uid}': {e}"
            )));
        }

        // Stamp rotation dates on the new key.
        if let Some(days) = interval_days {
            let today = OffsetDateTime::now_utc().date();
            let end = today + time::Duration::days(days);
            self.database
                .set_key_rotation_dates(&new_uid, Some(today), Some(end))
                .await
                .map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "Failed to set rotation dates on new HSM key '{new_uid}': {e}"
                    ))
                })?;
        }

        // Update CKA_LABEL on old key (remove @latest) and new key (add @latest).
        // Use `base_id` (without generation suffix) in the label — the generation is
        // already in its own field, and including a generation-suffixed key_id would
        // introduce extra `::` delimiters that break `parse_label_metadata()`.
        if let Some(ref name) = rotate_name {
            let old_label_retired = format!("{name}::{old_rotate_gen}::{base_id}");
            let new_label_latest = format!("{name}::{new_gen}::{base_id}@latest");

            self.database
                .set_key_label(uid, &old_label_retired)
                .await
                .map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "Failed to update CKA_LABEL on old HSM key '{uid}': {e}"
                    ))
                })?;
            self.database
                .set_key_label(&new_uid, &new_label_latest)
                .await
                .map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "Failed to set CKA_LABEL on new HSM key '{new_uid}': {e}"
                    ))
                })?;
        }

        trace!("HSM ReKey: old={uid} → new={new_uid} (slot={slot_id}, gen={new_gen}), user={user}");

        // Re-wrap any DB keys that were wrapped by the old HSM key, so that
        // they remain accessible under the new generation without requiring
        // the caller to keep the old HSM key alive.
        let mut operations: Vec<AtomicOperation> = Vec::new();
        Box::pin(self.rewrap_dependants(user, uid, &new_uid, &mut operations)).await?;
        if !operations.is_empty() {
            self.database
                .atomic(user, &operations)
                .await
                .map_err(KmsError::Database)?;
        }

        Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        })
    }
}
