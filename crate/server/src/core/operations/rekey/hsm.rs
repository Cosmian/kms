//! HSM-resident key rotation via PKCS#11.
//!
//! This module handles `ReKey` (AES keys) and `ReKeyKeyPair` (RSA/EC key pairs) for keys
//! whose UID starts with `hsm::` — non-extractable key material managed by a hardware
//! token.  The rotation algorithm generates a new key (`C_GenerateKey`) or key pair
//! (`C_GenerateKeyPair`) on the same HSM slot, assigns a generation-suffixed UID, and
//! updates `CKA_LABEL` / `CKA_START_DATE` / `CKA_END_DATE` on both old and new keys.
//!
//! It deliberately does not implement `RekeyOperation`: that pipeline builds replacement
//! objects in memory and commits them with a version-conditional SQL batch, none of which
//! applies to PKCS#11 (generation happens on the token, there are no object versions and
//! retirement lives in `CKA_LABEL`).

use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            KmipOperation,
            extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
            kmip_objects::ObjectType,
            kmip_operations::{ReKeyKeyPairResponse, ReKeyResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::trace;
use time::OffsetDateTime;

use crate::{
    core::{KMS, uid_utils::ObjectHandle},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

impl KMS {
    /// Find the latest generation UID in a keyset identified by `rotate_name`.
    async fn latest_hsm_keyset_uid(&self, rotate_name: &str, user: &UserId) -> Option<String> {
        self.database
            .find_by_rotate_name_uncached(rotate_name, None, user)
            .await
            .ok()
            .and_then(|keys| {
                keys.into_iter()
                    .max_by_key(|(_, attrs)| attrs.rotate_generation.unwrap_or(0))
                    .map(|(uid, _)| uid)
            })
    }

    /// Resolve a missing HSM key by falling back to keyset-name resolution.
    ///
    /// Looks up the latest-generation key for `full_base_uid` as a keyset name and
    /// delegates to [`Self::rekey_hsm`]. Returns an `Item_Not_Found` error
    /// if no keyset exists under that name.
    async fn hsm_keyset_fallback(
        &self,
        uid: &str,
        full_base_uid: &str,
        user: &UserId,
        object_type: ObjectType,
    ) -> KResult<String> {
        if let Some(latest) = self.latest_hsm_keyset_uid(full_base_uid, user).await {
            Box::pin(self.rekey_hsm(&latest, user, object_type, false)).await
        } else {
            Err(hsm_key_not_found(uid, full_base_uid))
        }
    }

    /// Write `CKA_LABEL` of an HSM key; `context` completes "Failed to …" in the error.
    async fn set_hsm_label(&self, uid: &str, label: &str, context: &str) -> KResult<()> {
        self.database
            .set_key_label(uid, label)
            .await
            .map_err(|e| KmsError::InvalidRequest(format!("Failed to {context} '{uid}': {e}")))
    }

    /// Rotate an HSM-resident AES key and return the UID of the new key.
    ///
    /// `pinned`: the caller addressed one generation (`name@first`, `name@0`), so a
    /// non-latest key is refused instead of redirected to the keyset head.
    pub(super) async fn rekey_hsm_symmetric(
        &self,
        uid: &str,
        user: &UserId,
        pinned: bool,
    ) -> KResult<ReKeyResponse> {
        let new_uid = Box::pin(self.rekey_hsm(uid, user, ObjectType::SymmetricKey, pinned)).await?;
        Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        })
    }

    /// Rotate an HSM-resident key pair, identified by its private key UID.
    ///
    /// `pinned`: see [`Self::rekey_hsm_symmetric`].
    pub(super) async fn rekey_hsm_keypair(
        &self,
        uid: &str,
        user: &UserId,
        pinned: bool,
    ) -> KResult<ReKeyKeyPairResponse> {
        let new_uid = Box::pin(self.rekey_hsm(uid, user, ObjectType::PrivateKey, pinned)).await?;
        let public_uid = format!("{new_uid}{SYSTEM_TAG_PUBLIC_KEY}");
        Ok(ReKeyKeyPairResponse {
            private_key_unique_identifier: UniqueIdentifier::TextString(new_uid),
            public_key_unique_identifier: UniqueIdentifier::TextString(public_uid),
        })
    }

    /// Rotate an HSM-resident AES key (`object_type == SymmetricKey`) or key pair
    /// (`object_type == PrivateKey`) and return the UID of the new (private) key.
    ///
    /// ## Rotation algorithm
    ///
    /// 1. Validate that the caller has `Rekey` permission.
    /// 2. Retrieve the old key's metadata from the HSM (algorithm, length, sensitivity,
    ///    keyset info from `CKA_LABEL`, rotation interval from `CKA_START_DATE`/`CKA_END_DATE`).
    /// 3. Compute the new generation number and new `key_id`/UID
    ///    (`base_key_id@new_gen`, `prefix::slot::base_key_id@new_gen`). A key that never
    ///    joined a keyset is enrolled under its full base UID.
    /// 4. Generate the new key on the same HSM slot via `C_GenerateKey` (`create`) or, for a
    ///    key pair, `C_GenerateKeyPair` (`atomic`; the public key UID is the private key UID
    ///    plus `_pk`).
    /// 5. Infer the rotation interval from the old key's dates; stamp new `CKA_START_DATE` /
    ///    `CKA_END_DATE` on the new (private) key if an interval is known.
    /// 6. Update `CKA_LABEL` on the old key (strip `@latest`) and on the new key
    ///    (append `@latest`); for a key pair, on both public keys as well.
    ///
    /// ## Non-latest generation rejection
    ///
    /// If the key belongs to a named keyset but is not the latest generation, the request
    /// is rejected when the caller addressed that generation (`@N` UID, or `pinned` for
    /// `name@first` / `name@0`); a bare base UID is redirected to the keyset head.
    async fn rekey_hsm(
        &self,
        uid: &str,
        user: &UserId,
        object_type: ObjectType,
        pinned: bool,
    ) -> KResult<String> {
        self.enforce_create_permission(user).await?;
        let op_name = if object_type == ObjectType::SymmetricKey {
            "ReKey"
        } else {
            "ReKeyKeyPair"
        };

        // Parse the UID early — prefix, slot_id, and key_id are needed for the
        // keyset-name fallback resolution that follows.
        let parsed = ObjectHandle::from(uid).hsm_parts()?;
        let full_base_uid = parsed.full_base_uid();
        let (prefix, slot_id, base_id, old_gen, has_explicit_gen) = (
            &parsed.prefix,
            parsed.slot_id,
            &parsed.base_id,
            parsed.generation,
            parsed.has_explicit_gen,
        );

        // Only a bare keyset handle can fall back to its current head. A missing addressed
        // generation must never silently rotate a different key.
        let old_owm = match self.database.retrieve_object(uid).await {
            Ok(owm) => owm,
            Err(e) if e.to_string().to_lowercase().contains("not found") => None,
            Err(e) => return Err(KmsError::Database(e)),
        };
        let Some(old_owm) = old_owm else {
            if has_explicit_gen || pinned {
                return Err(hsm_key_not_found(uid, &full_base_uid));
            }
            let fallback = self.hsm_keyset_fallback(uid, &full_base_uid, user, object_type);
            return Box::pin(fallback).await;
        };

        // Per-object authorization, before anything about the key is disclosed: the caller
        // must own the key or hold an explicit Rekey grant.  `enforce_create_permission`
        // above only checks the server-level "can create" right.  A caller with no grant at
        // all gets the same answer as for a missing key (COSMIAN-2026-037).
        if !self
            .user_can_perform_operation(&old_owm, user, &KmipOperation::Rekey)
            .await?
        {
            let has_grant = !self
                .database
                .list_user_operations_on_object(uid, user, true)
                .await?
                .is_empty();
            return Err(if has_grant {
                KmsError::Unauthorized(format!(
                    "User '{user}' does not have Rekey permission on HSM key '{uid}'"
                ))
            } else {
                hsm_key_not_found(uid, &full_base_uid)
            });
        }

        if old_owm.object().object_type() != object_type {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                if object_type == ObjectType::SymmetricKey {
                    "HSM ReKey is supported for AES symmetric keys only; re-key an HSM key pair \
                     with ReKeyKeyPair on its private key"
                } else {
                    "HSM ReKeyKeyPair requires the UID of an HSM private key"
                }
                .to_owned(),
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
        // - Addressed generation (`@N` suffix, or `pinned`): the caller targeted a specific
        //   old generation — this is an error.  Use the base UID to always rotate the head.
        // - Bare base UID (no @N): treat as a stable keyset handle and redirect silently
        //   to the actual latest.  For HSM keys rotate_name is the full base UID, which
        //   is unique across slots (embed slot ID).
        if !self.is_keyset_latest(uid, old_attrs, user).await? {
            if has_explicit_gen || pinned {
                return Err(KmsError::InvalidRequest(format!(
                    "{op_name}: HSM key '{uid}' (generation {old_gen}) is not the latest in its \
                     keyset — only the latest generation can be rotated. Use '{full_base_uid}' \
                     or '{full_base_uid}@latest' to rotate the current head."
                )));
            }
            // Stable handle: redirect to the latest generation.
            // rotate_name is the full base UID (unique across slots); fall back to
            // full_base_uid for keys whose rotation policy has not been initialised.
            let keyset_id = old_attrs.rotate_name.as_deref().unwrap_or(&full_base_uid);
            if let Some(latest_uid) = self.latest_hsm_keyset_uid(keyset_id, user).await
                && latest_uid != uid
            {
                return Box::pin(self.rekey_hsm(&latest_uid, user, object_type, false)).await;
            }
        }

        let new_gen = old_gen.checked_add(1).ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "{op_name}: HSM key '{uid}' is at the maximum generation {old_gen}"
            ))
        })?;
        let new_uid = format!("{prefix}::{slot_id}::{base_id}@{new_gen}");

        // A key that never joined a keyset is enrolled under its full base UID.
        let rotate_name = old_attrs
            .rotate_name
            .clone()
            .unwrap_or_else(|| full_base_uid.clone());
        let old_rotate_gen = old_attrs.rotate_generation.unwrap_or(old_gen);

        // Read rotation interval in days from the old key's attributes.
        // For HSM keys, rotate_interval is not stored in PKCS#11 as a KMIP attribute
        // (HsmStore::update_object is a no-op); instead it is reconstructed at
        // retrieve-time from CKA_START_DATE / CKA_END_DATE as (end − start) × (24 * 60 * 60) s.
        // If unavailable (key was never armed with SetAttribute RotateInterval),
        // interval_days is None and the new key will not be auto-scheduled.
        let interval_days: Option<i64> = old_attrs.rotate_interval.filter(|&i| i > 0).map(|secs| {
            secs / cosmian_kms_server_database::reexport::cosmian_kms_interfaces::SECS_PER_DAY
        });

        // The HSM carries no `PublicKeyLink`: the pair is derived from the `_pk` UID rule
        // of `HsmStore::atomic`. Retrieving it first (it checks `Rekey`) fails before any
        // change on the token when the public key is missing.
        let key_pair = if object_type == ObjectType::PrivateKey {
            let old_pk_uid = format!("{uid}{SYSTEM_TAG_PUBLIC_KEY}");
            let new_pk_uid = format!("{new_uid}{SYSTEM_TAG_PUBLIC_KEY}");
            let old_pk_owm = self.retrieve_linked_public_key(&old_pk_uid, user).await?;
            Some((old_pk_uid, new_pk_uid, old_pk_owm))
        } else {
            None
        };

        self.constraints
            .check(old_owm.object().object_type(), old_attrs)?;
        // Generate the new key (or key pair) on the same HSM slot.
        let generated = if let Some((_, new_pk_uid, old_pk_owm)) = &key_pair {
            self.database
                .atomic(
                    user,
                    &[
                        AtomicOperation::Create((
                            new_uid.clone(),
                            user.to_owned(),
                            old_owm.object().clone(),
                            old_attrs.clone(),
                            HashSet::new(),
                        )),
                        AtomicOperation::Create((
                            new_pk_uid.clone(),
                            user.to_owned(),
                            old_pk_owm.object().clone(),
                            old_pk_owm.attributes().clone(),
                            HashSet::new(),
                        )),
                    ],
                )
                .await
                .map(|_| ())
        } else {
            self.database
                .create(
                    Some(new_uid.clone()),
                    user,
                    &old_owm.object().clone(),
                    old_attrs,
                    &HashSet::new(),
                )
                .await
                .map(|_| ())
        };
        if let Err(e) = generated {
            if e.to_string().contains("already exists") {
                let latest_uid = self.latest_hsm_keyset_uid(&rotate_name, user).await;
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
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Object_Already_Exists,
                    format!(
                        "HSM key '{new_uid}' already exists — generation {new_gen} was already \
                         created on this HSM slot. A previous rotation may have \
                         completed.{retry_hint}"
                    ),
                ));
            }
            return Err(KmsError::InvalidRequest(format!(
                "Failed to generate new HSM key '{new_uid}': {e}"
            )));
        }

        // Stamp rotation dates on the new key (the private key for a key pair).
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
        self.set_hsm_label(
            uid,
            &format!("{rotate_name}::{old_rotate_gen}::{base_id}"),
            "update CKA_LABEL on old HSM key",
        )
        .await?;
        self.set_hsm_label(
            &new_uid,
            &format!("{rotate_name}::{new_gen}::{base_id}@latest"),
            "set CKA_LABEL on new HSM key",
        )
        .await?;
        // The public keys form their own keyset, named after the public key's full base UID
        // (what `SetAttribute` requires as an HSM keyset name).
        if let Some((old_pk_uid, new_pk_uid, _)) = &key_pair {
            let pk_name = format!("{rotate_name}{SYSTEM_TAG_PUBLIC_KEY}");
            let pk_id = format!("{base_id}{SYSTEM_TAG_PUBLIC_KEY}");
            self.set_hsm_label(
                old_pk_uid,
                &format!("{pk_name}::{old_rotate_gen}::{pk_id}"),
                "update CKA_LABEL on old HSM key",
            )
            .await?;
            self.set_hsm_label(
                new_pk_uid,
                &format!("{pk_name}::{new_gen}::{pk_id}@latest"),
                "set CKA_LABEL on new HSM key",
            )
            .await?;
            self.database.invalidate_rotate_name_cache(&pk_name);
        }
        // Make the new generation visible to Sign/Verify/Encrypt/Decrypt immediately
        // instead of waiting out the cache's TTL (see `RotateNameCache` module docs) —
        // this is the commit point: CKA_LABEL on both keys now reflects the rotation.
        self.database.invalidate_rotate_name_cache(&rotate_name);

        trace!("HSM ReKey: old={uid} → new={new_uid} (slot={slot_id}, gen={new_gen}), user={user}");

        // Re-wrap any DB keys that were wrapped by the old HSM key (the old public key for
        // a key pair), so that they remain accessible under the new generation without
        // requiring the caller to keep the old HSM key alive.
        let (old_wrapper, new_wrapper) = match &key_pair {
            Some((old_pk_uid, new_pk_uid, _)) => (old_pk_uid.as_str(), new_pk_uid.as_str()),
            None => (uid, new_uid.as_str()),
        };
        let mut operations: Vec<AtomicOperation> = Vec::new();
        Box::pin(self.rewrap_dependants(
            user,
            ObjectHandle::from(old_wrapper),
            ObjectHandle::from(new_wrapper),
            None,
            &mut operations,
        ))
        .await?;
        if !operations.is_empty() {
            self.database
                .atomic(user, &operations)
                .await
                .map_err(KmsError::Database)?;
        }

        Ok(new_uid)
    }
}

/// `Item_Not_Found` for an HSM key that is missing, or hidden from a caller without any grant.
fn hsm_key_not_found(uid: &str, full_base_uid: &str) -> KmsError {
    KmsError::Kmip21Error(
        ErrorReason::Item_Not_Found,
        format!(
            "HSM key '{uid}' not found and no keyset named '{full_base_uid}' exists on this HSM \
             slot"
        ),
    )
}

/// Hide the resolved generation in errors: callers without a grant must only see their
/// supplied identifier, whether the keyset is missing or resolves to an inaccessible head.
pub(super) fn conceal_hsm_rekey_error(error: KmsError, requested: &str) -> KmsError {
    match error {
        KmsError::ItemNotFound(_) | KmsError::Kmip21Error(ErrorReason::Item_Not_Found, _) => {
            KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("HSM key '{requested}' not found"),
            )
        }
        other => other,
    }
}
