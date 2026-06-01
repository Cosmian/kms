use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_operations::{Create, ReKey, ReKeyResponse},
    kmip_types::UniqueIdentifier,
};
use cosmian_logger::trace;
use time::OffsetDateTime;

use super::common::{
    RekeyOperation, ReplacementObject, RotationCandidate, compute_rotation_uid,
    enforce_privileged_user, execute_rekey, finalize_replacement_key,
    prepare_replacement_attributes, preserve_wrapping_key_link, retrieve_eligible_keys,
    set_rotation_metadata_on_new_key, validate_no_crypto_param_change,
};
use crate::{
    core::{
        KMS,
        operations::key_ops::{ObjectWithMetadataOps, reject_protection_storage_masks},
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

/// KMIP `ReKey` operation for symmetric keys (KMIP 2.1 §6.1.46).
///
/// - Generates fresh key material with the same algorithm and length.
/// - Assigns a new UID (preserving user-facing name prefixes across rotations).
/// - Handles wrapped keys: unwraps → generates → re-wraps with same wrapping key.
/// - Phase-1/Phase-2 commit for wrapping keys: re-wraps all dependant keys.
/// - Sets rotation metadata on both old and new keys.
pub(crate) async fn rekey(kms: &KMS, request: ReKey, owner: &str) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);
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
        return rekey_hsm_symmetric(kms, uid_or_tags, owner).await;
    }

    let offset = request.offset;
    execute_rekey(&SymmetricRekey { offset }, kms, &request, owner).await
}

impl RekeyOperation for SymmetricRekey {
    type Request = ReKey;
    type Response = ReKeyResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReKey,
        user: &str,
    ) -> KResult<Vec<RotationCandidate>> {
        reject_protection_storage_masks(request.protection_storage_masks.is_some())?;

        enforce_privileged_user(kms, user).await?;

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

        for owm in retrieve_eligible_keys(kms, uid_or_tags, ObjectType::SymmetricKey).await? {
            if !owm
                .user_can_perform_operation(user, &KmipOperation::Rekey, kms)
                .await?
            {
                continue;
            }

            // Reject Re-Key on a retired (non-latest) member of a named keyset.
            // Keys without a rotate_name are not keyset members and may be freely re-keyed.
            if owm.attributes().rotate_name.is_some()
                && owm.attributes().rotate_latest == Some(false)
            {
                return Err(KmsError::InvalidRequest(format!(
                    "ReKey: key '{}' is not the latest in its keyset — only the latest \
                     generation can be rotated",
                    owm.id()
                )));
            }

            // Reject requests that attempt to change crypto parameters
            validate_no_crypto_param_change(
                owm.attributes(),
                [request.attributes.as_ref()],
                "ReKey",
            )?;

            let uid = owm.id().to_owned();
            return Ok(vec![RotationCandidate {
                owm,
                uid,
                object_type: ObjectType::SymmetricKey,
            }]);
        }

        Err(KmsError::InvalidRequest(format!(
            "rekey: no active symmetric key found for uid/tags: {uid_or_tags}",
        )))
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate],
    ) -> KResult<Vec<ReplacementObject>> {
        let candidate = candidates
            .first()
            .ok_or_else(|| KmsError::InvalidRequest("no rotation candidate".to_owned()))?;

        // Clean attributes for generation
        let mut gen_attrs = candidate.owm.attributes().to_owned();
        gen_attrs.unique_identifier = None;
        gen_attrs.key_format_type = None;
        gen_attrs.link = None;
        gen_attrs.rotate_interval = None;
        gen_attrs.rotate_name = None;
        gen_attrs.rotate_offset = None;

        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: gen_attrs,
            protection_storage_masks: None,
        };
        let (_, new_object, new_tags) =
            KMS::create_symmetric_key_and_tags(kms.vendor_id(), &create_request)?;

        let new_uid = compute_rotation_uid(&candidate.uid);

        Ok(vec![ReplacementObject {
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
        candidates: &[RotationCandidate],
        replacements: &mut [ReplacementObject],
    ) -> KResult<()> {
        let candidate = candidates
            .first()
            .ok_or_else(|| KmsError::InvalidRequest("no rotation candidate".to_owned()))?;
        let replacement = replacements
            .first_mut()
            .ok_or_else(|| KmsError::InvalidRequest("no replacement object".to_owned()))?;

        let new_attrs = prepare_replacement_attributes(
            candidate.owm.attributes(),
            &candidate.uid,
            self.offset,
        )?;

        finalize_replacement_key(
            replacement,
            &new_attrs,
            ObjectType::SymmetricKey,
            &candidate.uid,
            None,
            kms.vendor_id(),
        )?;

        // Preserve WrappingKeyLink if the old key was wrapped
        preserve_wrapping_key_link(candidate.owm.object(), &mut replacement.attributes)?;

        // Set rotation metadata
        set_rotation_metadata_on_new_key(&mut replacement.attributes, candidate.owm.attributes())?;

        // Rewrap dependants to the NEW key
        replacement.rewrap_to = Some(replacement.new_uid.clone());

        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject]) -> ReKeyResponse {
        ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(
                replacements
                    .first()
                    .map_or_else(String::new, |r| r.new_uid.clone()),
            ),
        }
    }
}
