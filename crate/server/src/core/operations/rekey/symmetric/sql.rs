//! SQL-backed symmetric key rotation (KMIP `ReKey` §6.1.46).
//!
//! This module handles `ReKey` for keys stored in the SQL database — generates fresh
//! key material, manages wrapping/unwrapping, links generations, and retires old keys.

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

use super::super::common::{RekeyOperation, ReplacementObject, RotationCandidate, execute_rekey};
use crate::{
    core::{KMS, operations::key_ops::KeySelectionSpec},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Implementor of [`RekeyOperation`] for KMIP `ReKey` (KMIP 2.1 §6.1.46) on SQL-backed
/// symmetric keys.
pub(in crate::core::operations::rekey) struct SqlSymmetricRekeyer {
    /// The `Offset` from the `ReKey` request — an interval added to the new key's
    /// `Initial Date` to compute its `Activation Date` (KMIP 2.1 §6.1.46 Table 305).
    pub offset: Option<i64>,
}

impl KeySelectionSpec for SqlSymmetricRekeyer {
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

impl SqlSymmetricRekeyer {
    /// Execute the SQL-backed symmetric rekey via the generic [`RekeyOperation`] pipeline.
    pub(super) async fn execute(
        &self,
        kms: &KMS,
        request: &ReKey,
        owner: &str,
    ) -> KResult<ReKeyResponse> {
        Box::pin(execute_rekey(self, kms, request, owner)).await
    }
}

impl RekeyOperation for SqlSymmetricRekeyer {
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

        // HSM-managed keys cannot be re-keyed via the SQL pipeline: they have no KMIP
        // attribute storage and are often non-extractable (CKA_EXTRACTABLE = false).
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
        kms.enforce_keyset_latest(owm.id(), owm.attributes(), user, "ReKey")
            .await?;

        let uid = owm.id().to_owned();
        Ok([RotationCandidate { owm, uid }])
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
