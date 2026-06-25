use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{Create, ReKey, ReKeyResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;
use time::OffsetDateTime;

use super::common::{RekeyOperation, ReplacementObject, RotationCandidate, execute_rekey};
use crate::{
    core::{
        KMS,
        operations::key_ops::KeySelectionSpec,
        uid_utils::{has_prefix, parse_keyset_identifier, resolve_keyset_to_single_uid},
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Implementor of [`RekeyOperation`] for KMIP `ReKey` (KMIP 2.1 §6.1.46) on symmetric keys.
pub(crate) struct SymmetricRekey {
    /// The `Offset` from the `ReKey` request — an interval added to the new key's
    /// `Initial Date` to compute its `Activation Date` (KMIP 2.1 §6.1.46 Table 305).
    offset: Option<i64>,
}

impl KeySelectionSpec for SymmetricRekey {
    const KMIP_OP: KmipOperation = KmipOperation::Rekey;
    const OP_NAME: &'static str = "ReKey";

    fn accepted_states() -> &'static [State] {
        &[State::Active, State::Deactivated, State::Compromised]
    }

    fn strict_permission_check() -> bool {
        true
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        owm.object().object_type() == ObjectType::SymmetricKey
    }
}

/// KMIP `ReKey` operation for symmetric keys (KMIP 2.1 §6.1.46).
///
/// - For regular (SQL) keys: generates fresh key material, handles wrapping, links generations.
/// - For HSM-resident keys (UID starts with `hsm::`): calls `C_GenerateKey` on the same HSM
///   slot, assigns a generation-suffix UID (`original::N+1`), and updates `CKA_LABEL` /
///   `CKA_START_DATE` / `CKA_END_DATE` on both the old and new keys.
pub(crate) async fn rekey(kms: &KMS, request: ReKey, owner: &str) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ReKey: the unique identifier must be a string")?;

    // Resolve keyset references (`name@latest`, `name@first`, `name@N`, bare name) to a
    // concrete UID before routing. This allows `re-key --key-id my-keyset@latest` to work
    // transparently for both SQL and HSM-backed keysets.
    let request = if let Some(keyset_ref) = parse_keyset_identifier(uid_or_tags) {
        if let Some(resolved) = resolve_keyset_to_single_uid(&keyset_ref, kms, owner).await? {
            trace!(
                "ReKey: resolved keyset ref '{}' → '{}'",
                uid_or_tags, resolved
            );
            ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(resolved)),
                ..request
            }
        } else {
            return Err(KmsError::InvalidRequest(format!(
                "ReKey: keyset '{uid_or_tags}' not found or has no resolvable latest key"
            )));
        }
    } else {
        request
    };

    // uid_or_tags may now differ from the resolved UID — re-read from the (possibly updated) request.
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ReKey: the unique identifier must be a string")?;

    // Route HSM-resident keys through the dedicated PKCS#11 rotation path.
    // The general RekeyOperation pipeline is designed for SQL-backed keys and
    // is not applicable to non-extractable HSM key material.
    if has_prefix(uid_or_tags).is_some() {
        return kms.rekey_hsm_symmetric(uid_or_tags, owner).await;
    }

    Box::pin(execute_rekey(
        &SymmetricRekey {
            offset: request.offset,
        },
        kms,
        &request,
        owner,
    ))
    .await
}

impl KMS {
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
    /// 6. Update `CKA_LABEL` on the old key (strip `::latest` suffix) and on the new key
    ///    (append `::latest`).
    async fn rekey_hsm_symmetric(&self, uid: &str, user: &str) -> KResult<ReKeyResponse> {
        self.enforce_create_permission(user).await?;

        // Retrieve old key metadata from the HSM.
        let old_owm = self
            .database
            .retrieve_object(uid)
            .await?
            .ok_or_else(|| KmsError::InvalidRequest(format!("HSM key '{uid}' not found")))?;

        if old_owm.object().object_type() != ObjectType::SymmetricKey {
            return Err(KmsError::NotSupported(
                "HSM ReKey is currently supported for AES symmetric keys only".to_owned(),
            ));
        }

        let old_attrs = old_owm.attributes();

        // Reject Re-Key on a retired (non-latest) member of a named keyset.
        // Keys without a rotate_name are not keyset members and may be freely re-keyed.
        if old_attrs.rotate_name.is_some() && !self.is_keyset_latest(uid, old_attrs, user).await? {
            return Err(KmsError::InvalidRequest(format!(
                "ReKey: HSM key '{uid}' is not the latest in its keyset — only the latest \
                 generation can be rotated"
            )));
        }

        // Parse the UID to extract prefix, slot_id, and key_id.
        // For `hsm::softhsm2::0::mykey` → prefix = `"hsm::softhsm2"`, rest = `"0::mykey"`.
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

        // Compute the new generation and new key_id.
        // `key_id` may already contain a generation suffix: `"base_id::N"`.
        // We split on the last `::` to find any existing numeric generation suffix.
        let (base_id, old_gen) = key_id
            .rsplit_once("::")
            .map_or((key_id, 0), |(base, suffix)| {
                suffix.parse::<i32>().map_or((key_id, 0), |n| (base, n))
            });

        let new_gen = old_gen + 1;
        let new_key_id = format!("{base_id}::{new_gen}");
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
        self.database
            .create(
                Some(new_uid.clone()),
                user,
                &old_owm.object().clone(),
                old_attrs,
                &std::collections::HashSet::new(),
            )
            .await
            .map_err(|e| {
                KmsError::InvalidRequest(format!("Failed to generate new HSM key '{new_uid}': {e}"))
            })?;

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

        // Update CKA_LABEL on old key (remove ::latest) and new key (add ::latest).
        // Use `base_id` (without generation suffix) in the label — the generation is
        // already in its own field, and including a generation-suffixed key_id would
        // introduce extra `::` delimiters that break `parse_label_metadata()`.
        if let Some(ref name) = rotate_name {
            let old_label_retired = format!("{name}::{old_rotate_gen}::{base_id}");
            let new_label_latest = format!("{name}::{new_gen}::{base_id}");

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

        Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        })
    }
}

impl RekeyOperation for SymmetricRekey {
    type Candidates = [RotationCandidate; 1];
    type Replacements = [ReplacementObject; 1];
    type Request = ReKey;
    type Response = ReKeyResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReKey,
        user: &str,
    ) -> KResult<[RotationCandidate; 1]> {
        KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

        kms.enforce_create_permission(user).await?;

        let uid_or_tags = request
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?
            .as_str()
            .context("Rekey: the symmetric key unique identifier must be a string")?;

        // HSM-managed keys cannot be re-keyed via KMIP: they have no KMIP attribute
        // storage and are often non-extractable (CKA_EXTRACTABLE = false).
        // Use PKCS#11 vendor tools for HSM key lifecycle management.
        if uid_or_tags.starts_with("hsm::") {
            return Err(KmsError::NotSupported(
                "Re-Key is not supported for HSM-managed keys. \
                 Use PKCS#11 vendor tools or the HSM administration console \
                 to manage HSM key lifecycle."
                    .to_owned(),
            ));
        }

        let candidates = kms
            .retrieve_eligible_keys(uid_or_tags, ObjectType::SymmetricKey)
            .await?;

        let owm = kms
            .select_unique_key::<Self, _>(candidates, uid_or_tags, user, |owm| {
                // Reject requests that attempt to change crypto parameters
                owm.attributes()
                    .validate_no_crypto_param_change([request.attributes.as_ref()], "ReKey")?;
                Ok(())
            })
            .await?;

        // Reject Re-Key on a retired (non-latest) member of a named keyset.
        if !kms
            .is_keyset_latest(owm.id(), owm.attributes(), user)
            .await?
        {
            return Err(KmsError::InvalidRequest(format!(
                "ReKey: key '{}' is not the latest in its keyset — only the latest \
                     generation can be rotated",
                owm.id()
            )));
        }

        let uid = owm.id().to_owned();
        Ok([RotationCandidate {
            owm,
            uid,
            object_type: ObjectType::SymmetricKey,
        }])
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
    ) -> KResult<[ReplacementObject; 1]> {
        let [candidate] = candidates;

        // Clean attributes for generation (removes identity, lifecycle dates, rotation metadata)
        let gen_attrs = candidate
            .owm
            .attributes()
            .clean_for_generation(kms.vendor_id());

        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: gen_attrs,
            protection_storage_masks: None,
        };
        let (_, new_object, new_tags) =
            KMS::create_symmetric_key_and_tags(kms.vendor_id(), &create_request)?;

        let new_uid = UniqueIdentifier::rotation_successor(
            candidate.owm.attributes().rotate_name.as_deref(),
            candidate.owm.attributes().rotate_generation,
        );

        Ok([ReplacementObject {
            new_uid,
            old_uid: candidate.uid.clone(),
            object: new_object,
            attributes: Attributes::default(), // filled in prepare_attributes
            tags: new_tags,
            rewrap_to: Some(candidate.uid.clone()), // placeholder, replaced in prepare_attributes
        }])
    }

    fn prepare_attributes(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 1],
        replacements: &mut [ReplacementObject; 1],
    ) -> KResult<()> {
        let [candidate] = candidates;
        let [replacement] = replacements;

        let new_attrs = candidate
            .owm
            .attributes()
            .for_replacement(&candidate.uid, self.offset)?;

        replacement.finalize(
            &new_attrs,
            ObjectType::SymmetricKey,
            &candidate.uid,
            None,
            kms.vendor_id(),
        )?;

        // Preserve WrappingKeyLink if the old key was wrapped
        candidate
            .owm
            .object()
            .copy_wrapping_key_link_to(&mut replacement.attributes);

        // Set rotation metadata
        replacement
            .attributes
            .set_rotation_metadata_from(candidate.owm.attributes())?;

        // Rewrap dependants to the NEW key
        replacement.rewrap_to = Some(replacement.new_uid.clone());

        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject; 1]) -> ReKeyResponse {
        let [replacement] = replacements;
        ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(replacement.new_uid.clone()),
        }
    }
}
