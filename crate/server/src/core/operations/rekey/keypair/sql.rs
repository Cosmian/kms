//! SQL-backed asymmetric key pair rotation (KMIP `ReKeyKeyPair` §6.1.47).
//!
//! This module handles `ReKeyKeyPair` for key pairs stored in the SQL database — generates
//! a fresh key pair, manages wrapping/unwrapping, links generations, and retires old keys.

use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{CreateKeyPair, ReKeyKeyPair, ReKeyKeyPairResponse},
            kmip_types::{KeyFormatType, LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use super::super::common::{RekeyOperation, ReplacementObject, RotationCandidate};
use crate::{
    core::{
        KMS,
        operations::{create_key_pair::generate_key_pair, key_ops::KeySelectionSpec},
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Implementor of [`RekeyOperation`] for KMIP `ReKeyKeyPair` (KMIP 1.4 §4.5 / KMIP 2.1
/// §6.1.47) on SQL-backed asymmetric key pairs.
pub(in crate::core::operations::rekey) struct SqlKeypairRekeyer {
    /// The `offset` from the `ReKeyKeyPair` request (date computation per KMIP 1.4 Table
    /// 176 / KMIP 2.1 Table 308).
    pub offset: Option<i64>,
}

impl KeySelectionSpec for SqlKeypairRekeyer {
    const KMIP_OP: KmipOperation = KmipOperation::Rekey;
    const OP_NAME: &'static str = "ReKeyKeyPair";

    fn accepted_states() -> &'static [State] {
        &[State::Active, State::Deactivated, State::Compromised]
    }

    fn strict_permission_check() -> bool {
        true
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        if owm.object().object_type() != ObjectType::PrivateKey {
            return false;
        }
        // Skip Covercrypt keys (handled separately before trait dispatch)
        let key_format_type = owm.attributes().key_format_type.or_else(|| {
            owm.object()
                .attributes()
                .ok()
                .and_then(|a| a.key_format_type)
        });
        key_format_type != Some(KeyFormatType::CoverCryptSecretKey)
    }
}

impl RekeyOperation for SqlKeypairRekeyer {
    type Candidates = [RotationCandidate; 2];
    type Replacements = [ReplacementObject; 2];
    type Request = ReKeyKeyPair;
    type Response = ReKeyKeyPairResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReKeyKeyPair,
        user: &str,
    ) -> KResult<[RotationCandidate; 2]> {
        KMS::reject_protection_storage_masks(
            request.common_protection_storage_masks.is_some()
                || request.private_protection_storage_masks.is_some()
                || request.public_protection_storage_masks.is_some(),
        )?;

        kms.enforce_create_permission(user).await?;

        let uid_or_tags = request
            .private_key_unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?
            .as_str()
            .context("ReKeyKeyPair: the private key unique identifier must be a string")?;

        // HSM-managed keys cannot be re-keyed via the SQL pipeline: they have no KMIP
        // attribute storage and are often non-extractable (CKA_EXTRACTABLE = false).
        if uid_or_tags.starts_with("hsm::") {
            return Err(KmsError::NotSupported(
                "Re-Key Key Pair is not supported for HSM-managed keys. \
                 Use PKCS#11 vendor tools or the HSM administration console \
                 to manage HSM key lifecycle."
                    .to_owned(),
            ));
        }

        let candidates = kms
            .retrieve_eligible_keys(uid_or_tags, ObjectType::PrivateKey)
            .await?;

        let owm = kms
            .select_unique_key::<Self, _>(candidates, uid_or_tags, user, |owm| {
                // Validate no crypto param changes
                owm.attributes().validate_no_crypto_param_change(
                    [
                        request.common_attributes.as_ref(),
                        request.private_key_attributes.as_ref(),
                        request.public_key_attributes.as_ref(),
                    ],
                    "ReKeyKeyPair",
                )?;
                Ok(())
            })
            .await?;

        // Reject Re-Key on a retired (non-latest) member of a named keyset.
        kms.enforce_keyset_latest(owm.id(), owm.attributes(), user, "ReKeyKeyPair")
            .await?;

        // Resolve paired public key (post-selection: only for the winning candidate)
        let old_sk_uid = owm.id().to_owned();
        let sk_candidate = RotationCandidate {
            uid: old_sk_uid,
            object_type: ObjectType::PrivateKey,
            owm,
        };
        let old_pk_uid = sk_candidate.public_key_uid()?;
        let old_pk_owm = kms.retrieve_linked_public_key(&old_pk_uid).await?;

        Ok([
            sk_candidate,
            RotationCandidate {
                uid: old_pk_uid,
                object_type: ObjectType::PublicKey,
                owm: old_pk_owm,
            },
        ])
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 2],
    ) -> KResult<[ReplacementObject; 2]> {
        let [sk_candidate, pk_candidate] = candidates;

        let common_attrs = sk_candidate
            .owm
            .attributes()
            .clean_for_generation(kms.vendor_id());
        let new_sk_uid = UniqueIdentifier::rotation_successor(
            sk_candidate.owm.attributes().rotate_name.as_deref(),
            sk_candidate.owm.attributes().rotate_generation,
        );
        // The public key UID always mirrors the private key UID with the "_pk" suffix.
        let new_pk_uid = format!("{new_sk_uid}_pk");

        // Propagate the CryptographicUsageMask from the old keys so that
        // FIPS-mode key-pair generators receive the required mask value.
        let sk_mask = sk_candidate
            .owm
            .attributes()
            .cryptographic_usage_mask
            .or_else(|| {
                sk_candidate
                    .owm
                    .object()
                    .attributes()
                    .ok()
                    .and_then(|a| a.cryptographic_usage_mask)
            });
        let pk_mask = pk_candidate
            .owm
            .attributes()
            .cryptographic_usage_mask
            .or_else(|| {
                pk_candidate
                    .owm
                    .object()
                    .attributes()
                    .ok()
                    .and_then(|a| a.cryptographic_usage_mask)
            });
        let private_key_attributes = sk_mask.map(|m| Attributes {
            cryptographic_usage_mask: Some(m),
            ..Attributes::default()
        });
        let public_key_attributes = pk_mask.map(|m| Attributes {
            cryptographic_usage_mask: Some(m),
            ..Attributes::default()
        });

        let create_kp_request = CreateKeyPair {
            common_attributes: Some(common_attrs),
            private_key_attributes,
            public_key_attributes,
            common_protection_storage_masks: None,
            private_protection_storage_masks: None,
            public_protection_storage_masks: None,
        };

        let key_pair =
            generate_key_pair(kms.vendor_id(), create_kp_request, &new_sk_uid, &new_pk_uid)?;

        Ok([
            ReplacementObject {
                new_uid: new_sk_uid,
                old_uid: sk_candidate.uid.clone(),
                object: key_pair.private_key().to_owned(),
                attributes: Attributes::default(), // filled in prepare_attributes
                tags: HashSet::new(),              // filled in prepare_attributes
                rewrap_to: None,                   // private keys are not wrapping keys
            },
            ReplacementObject {
                new_uid: new_pk_uid,
                old_uid: pk_candidate.uid.clone(),
                object: key_pair.public_key().to_owned(),
                attributes: Attributes::default(), // filled in prepare_attributes
                tags: HashSet::new(),              // filled in prepare_attributes
                rewrap_to: None,                   // set in prepare_attributes
            },
        ])
    }

    fn prepare_attributes(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate; 2],
        replacements: &mut [ReplacementObject; 2],
    ) -> KResult<()> {
        let [sk_candidate, pk_candidate] = candidates;

        let new_sk_attributes = sk_candidate
            .owm
            .attributes()
            .for_replacement(&sk_candidate.uid, self.offset)?;
        let new_pk_attributes = pk_candidate
            .owm
            .attributes()
            .for_replacement(&pk_candidate.uid, self.offset)?;

        let pk_new_uid = replacements[1].new_uid.clone();
        let sk_new_uid = replacements[0].new_uid.clone();

        let [sk_rep, pk_rep] = replacements;
        sk_rep.prepare_for_keypair(
            &new_sk_attributes,
            sk_candidate,
            &pk_new_uid,
            LinkType::PublicKeyLink,
            ObjectType::PrivateKey,
            false,
            kms.vendor_id(),
        )?;
        sk_rep
            .attributes
            .set_rotation_metadata_from(sk_candidate.owm.attributes())?;

        pk_rep.prepare_for_keypair(
            &new_pk_attributes,
            pk_candidate,
            &sk_new_uid,
            LinkType::PrivateKeyLink,
            ObjectType::PublicKey,
            true,
            kms.vendor_id(),
        )?;

        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject; 2]) -> ReKeyKeyPairResponse {
        let [sk_rep, pk_rep] = replacements;
        ReKeyKeyPairResponse {
            private_key_unique_identifier: UniqueIdentifier::TextString(sk_rep.new_uid.clone()),
            public_key_unique_identifier: UniqueIdentifier::TextString(pk_rep.new_uid.clone()),
        }
    }
}
