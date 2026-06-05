use std::collections::HashSet;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{CreateKeyPair, ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::{KeyFormatType, LinkType, UniqueIdentifier},
    },
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::cover_crypt::attributes::rekey_edit_action_from_attributes,
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_logger::trace;

use super::common::{
    RekeyOperation, ReplacementObject, RotationCandidate, compute_rotation_uid,
    enforce_privileged_user, execute_rekey, finalize_replacement_key,
    prepare_replacement_attributes, preserve_wrapping_key_link, retrieve_eligible_keys,
    set_rotation_metadata_on_new_key, validate_no_crypto_param_change,
};
#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::rekey_keypair_cover_crypt;
use crate::{
    core::{
        KMS,
        operations::{
            create_key_pair::generate_key_pair,
            key_ops::{ObjectWithMetadataOps, reject_protection_storage_masks},
        },
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Implementor of [`RekeyOperation`] for KMIP `ReKeyKeyPair` (KMIP 1.4 §4.5 / KMIP 2.1 §6.1.47) on asymmetric key pairs.
struct KeypairRekey {
    /// The `offset` from the `ReKeyKeyPair` request (date computation per KMIP 1.4 Table 176 / KMIP 2.1 Table 308).
    offset: Option<i64>,
}

/// KMIP `ReKeyKeyPair` operation for asymmetric key pairs.
///
/// Per KMIP 1.4 §4.5:
/// - Creates a replacement key pair with new Unique Identifiers.
/// - Sets `ReplacementObjectLink` on both old private and public keys.
/// - Sets `ReplacedObjectLink` on both new private and public keys.
/// - The replacement keys take over the Name attributes of the existing keys.
/// - The existing keys' State is NOT changed.
/// - If `offset` is provided, date computation per Table 176 is applied.
/// - Rotation metadata is set on both old and new keys.
///
/// For Covercrypt keys (non-FIPS only), delegates to the existing in-place
/// attribute-level rekey which mutates the key material without creating new UIDs.
pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &str,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("ReKeyKeyPair: {}", serde_json::to_string(&request)?);

    // Covercrypt early-return: uses a completely different code path (in-place attribute rekey)
    // that doesn't fit the rotation trait pattern.
    #[cfg(feature = "non-fips")]
    if let Some(response) = try_covercrypt_rekey(kms, &request, user).await? {
        return Ok(response);
    }

    execute_rekey(
        &KeypairRekey {
            offset: request.offset,
        },
        kms,
        &request,
        user,
    )
    .await
}

/// Attempt Covercrypt-specific rekey. Returns `Some(response)` if handled, `None` otherwise.
#[cfg(feature = "non-fips")]
async fn try_covercrypt_rekey(
    kms: &KMS,
    request: &ReKeyKeyPair,
    user: &str,
) -> KResult<Option<ReKeyKeyPairResponse>> {
    let uid_or_tags = request
        .private_key_unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ReKeyKeyPair: the private key unique identifier must be a string")?;

    for owm in retrieve_eligible_keys(kms, uid_or_tags, ObjectType::PrivateKey).await? {
        let key_format_type = owm.attributes().key_format_type.or_else(|| {
            owm.object()
                .attributes()
                .ok()
                .and_then(|a| a.key_format_type)
        });

        if key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
            let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReKeyKeyPair: the private key attributes must be supplied for Covercrypt"
                        .to_owned(),
                )
            })?;
            if Some(CryptographicAlgorithm::CoverCrypt) == attributes.cryptographic_algorithm {
                let action = rekey_edit_action_from_attributes(kms.vendor_id(), attributes)?;
                let response = Box::pin(rekey_keypair_cover_crypt(
                    kms,
                    Covercrypt::default(),
                    owm.id().to_owned(),
                    user,
                    action,
                    owm.attributes().sensitive.unwrap_or(false),
                ))
                .await
                .context("ReKeyKeyPair: Covercrypt rekey failed")?;
                return Ok(Some(response));
            }
        }
    }
    Ok(None)
}

impl RekeyOperation for KeypairRekey {
    type Request = ReKeyKeyPair;
    type Response = ReKeyKeyPairResponse;

    async fn validate(
        &self,
        kms: &KMS,
        request: &ReKeyKeyPair,
        user: &str,
    ) -> KResult<Vec<RotationCandidate>> {
        reject_protection_storage_masks(
            request.common_protection_storage_masks.is_some()
                || request.private_protection_storage_masks.is_some()
                || request.public_protection_storage_masks.is_some(),
        )?;

        enforce_privileged_user(kms, user).await?;

        let uid_or_tags = request
            .private_key_unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?
            .as_str()
            .context("ReKeyKeyPair: the private key unique identifier must be a string")?;

        // HSM-managed keys cannot be re-keyed via KMIP: they have no KMIP attribute
        // storage and are often non-extractable (CKA_EXTRACTABLE = false).
        // Use PKCS#11 vendor tools for HSM key lifecycle management.
        if uid_or_tags.starts_with("hsm::") {
            return Err(KmsError::NotSupported(
                "Re-Key Key Pair is not supported for HSM-managed keys. \
                 Use PKCS#11 vendor tools or the HSM administration console \
                 to manage HSM key lifecycle."
                    .to_owned(),
            ));
        }

        for owm in retrieve_eligible_keys(kms, uid_or_tags, ObjectType::PrivateKey).await? {
            if !owm
                .user_can_perform_operation(user, &KmipOperation::Rekey, kms)
                .await?
            {
                continue;
            }

            // Skip Covercrypt keys (handled separately before trait dispatch)
            let key_format_type = owm.attributes().key_format_type.or_else(|| {
                owm.object()
                    .attributes()
                    .ok()
                    .and_then(|a| a.key_format_type)
            });
            if key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                continue;
            }

            // Reject Re-Key on a retired (non-latest) member of a named keyset.
            // Keys without a rotate_name are not keyset members and may be freely re-keyed.
            if owm.attributes().rotate_name.is_some()
                && owm.attributes().rotate_latest == Some(false)
            {
                return Err(KmsError::InvalidRequest(format!(
                    "ReKeyKeyPair: key '{}' is not the latest in its keyset — only the \
                     latest generation can be rotated",
                    owm.id()
                )));
            }

            // Validate no crypto param changes
            validate_no_crypto_param_change(
                owm.attributes(),
                [
                    request.common_attributes.as_ref(),
                    request.private_key_attributes.as_ref(),
                    request.public_key_attributes.as_ref(),
                ],
                "ReKeyKeyPair",
            )?;

            // Resolve paired public key
            let old_sk_uid = owm.id().to_owned();
            let old_pk_uid = resolve_public_key_uid(&owm)?;
            let old_pk_owm = retrieve_linked_public_key(kms, &old_pk_uid).await?;

            return Ok(vec![
                RotationCandidate {
                    uid: old_sk_uid,
                    object_type: ObjectType::PrivateKey,
                    owm,
                },
                RotationCandidate {
                    uid: old_pk_uid,
                    object_type: ObjectType::PublicKey,
                    owm: old_pk_owm,
                },
            ]);
        }

        Err(KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            uid_or_tags.to_owned(),
        ))
    }

    async fn generate_replacement(
        &self,
        kms: &KMS,
        candidates: &[RotationCandidate],
    ) -> KResult<Vec<ReplacementObject>> {
        let sk_candidate = candidates
            .first()
            .ok_or_else(|| KmsError::InvalidRequest("missing private key candidate".to_owned()))?;
        let pk_candidate = candidates
            .get(1)
            .ok_or_else(|| KmsError::InvalidRequest("missing public key candidate".to_owned()))?;

        let common_attrs =
            build_generation_attributes(sk_candidate.owm.attributes(), kms.vendor_id());
        let new_sk_uid = compute_rotation_uid(&sk_candidate.uid);
        let new_pk_uid = compute_rotation_uid(&pk_candidate.uid);

        let create_kp_request = CreateKeyPair {
            common_attributes: Some(common_attrs),
            private_key_attributes: None,
            public_key_attributes: None,
            common_protection_storage_masks: None,
            private_protection_storage_masks: None,
            public_protection_storage_masks: None,
        };

        let key_pair =
            generate_key_pair(kms.vendor_id(), create_kp_request, &new_sk_uid, &new_pk_uid)?;

        Ok(vec![
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
        candidates: &[RotationCandidate],
        replacements: &mut [ReplacementObject],
    ) -> KResult<()> {
        let (sk_candidate, pk_candidate) = extract_keypair_candidates(candidates)?;

        let new_sk_attributes = prepare_replacement_attributes(
            sk_candidate.owm.attributes(),
            &sk_candidate.uid,
            self.offset,
        )?;
        let new_pk_attributes = prepare_replacement_attributes(
            pk_candidate.owm.attributes(),
            &pk_candidate.uid,
            self.offset,
        )?;

        if replacements.len() < 2 {
            kms_bail!(KmsError::InvalidRequest(
                "expected 2 replacements for key pair".to_owned()
            ));
        }

        let pk_new_uid = replacements
            .get(1)
            .ok_or_else(|| KmsError::InvalidRequest("missing PK replacement".to_owned()))?
            .new_uid
            .clone();
        let sk_new_uid = replacements
            .first()
            .ok_or_else(|| KmsError::InvalidRequest("missing SK replacement".to_owned()))?
            .new_uid
            .clone();

        let sk_rep = replacements
            .first_mut()
            .ok_or_else(|| KmsError::InvalidRequest("missing SK replacement".to_owned()))?;
        prepare_sk_replacement(
            sk_rep,
            &new_sk_attributes,
            sk_candidate,
            &pk_new_uid,
            kms.vendor_id(),
        )?;
        set_rotation_metadata_on_new_key(&mut sk_rep.attributes, sk_candidate.owm.attributes())?;

        let pk_rep = replacements
            .get_mut(1)
            .ok_or_else(|| KmsError::InvalidRequest("missing PK replacement".to_owned()))?;
        prepare_pk_replacement(
            pk_rep,
            &new_pk_attributes,
            pk_candidate,
            &sk_new_uid,
            kms.vendor_id(),
        )?;

        Ok(())
    }

    fn build_response(&self, replacements: &[ReplacementObject]) -> ReKeyKeyPairResponse {
        ReKeyKeyPairResponse {
            private_key_unique_identifier: UniqueIdentifier::TextString(
                replacements
                    .first()
                    .map_or_else(String::new, |r| r.new_uid.clone()),
            ),
            public_key_unique_identifier: UniqueIdentifier::TextString(
                replacements
                    .get(1)
                    .map_or_else(String::new, |r| r.new_uid.clone()),
            ),
        }
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Extract the SK and PK candidates from the candidates slice, validating length.
fn extract_keypair_candidates(
    candidates: &[RotationCandidate],
) -> KResult<(&RotationCandidate, &RotationCandidate)> {
    let sk = candidates
        .first()
        .ok_or_else(|| KmsError::InvalidRequest("missing private key candidate".to_owned()))?;
    let pk = candidates
        .get(1)
        .ok_or_else(|| KmsError::InvalidRequest("missing public key candidate".to_owned()))?;
    Ok((sk, pk))
}

/// Finalize the private key replacement: lifecycle setup, cross-link, and wrapping key.
fn prepare_sk_replacement(
    sk: &mut ReplacementObject,
    new_attrs: &Attributes,
    candidate: &RotationCandidate,
    pk_new_uid: &str,
    vendor_id: &str,
) -> KResult<()> {
    finalize_replacement_key(
        sk,
        new_attrs,
        ObjectType::PrivateKey,
        &candidate.uid,
        Some((pk_new_uid, LinkType::PublicKeyLink)),
        vendor_id,
    )?;
    preserve_wrapping_key_link(candidate.owm.object(), &mut sk.attributes)?;
    Ok(())
}

/// Finalize the public key replacement: lifecycle setup, cross-link, wrapping key, and `rewrap_to`.
fn prepare_pk_replacement(
    pk: &mut ReplacementObject,
    new_attrs: &Attributes,
    candidate: &RotationCandidate,
    sk_new_uid: &str,
    vendor_id: &str,
) -> KResult<()> {
    finalize_replacement_key(
        pk,
        new_attrs,
        ObjectType::PublicKey,
        &candidate.uid,
        Some((sk_new_uid, LinkType::PrivateKeyLink)),
        vendor_id,
    )?;
    preserve_wrapping_key_link(candidate.owm.object(), &mut pk.attributes)?;
    // Public key IS a wrapping key — dependants get re-wrapped to it
    pk.rewrap_to = Some(pk.new_uid.clone());
    Ok(())
}

/// Follow `PublicKeyLink` on the private key to resolve the paired public key UID.
fn resolve_public_key_uid(
    owm: &cosmian_kms_server_database::reexport::cosmian_kms_interfaces::ObjectWithMetadata,
) -> KResult<String> {
    owm.attributes()
        .get_link(LinkType::PublicKeyLink)
        .map(|l| l.to_string())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "ReKeyKeyPair: the private key has no PublicKeyLink. Cannot determine the \
                 paired public key."
                    .to_owned(),
            )
        })
}

/// Retrieve the linked public key from the database.
async fn retrieve_linked_public_key(
    kms: &KMS,
    pk_uid: &str,
) -> KResult<cosmian_kms_server_database::reexport::cosmian_kms_interfaces::ObjectWithMetadata> {
    kms.database
        .retrieve_objects(pk_uid)
        .await?
        .into_values()
        .next()
        .ok_or_else(|| {
            KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!("ReKeyKeyPair: linked public key '{pk_uid}' not found in database"),
            )
        })
}

/// Build clean attributes for key pair generation.
fn build_generation_attributes(old_attrs: &Attributes, vendor_id: &str) -> Attributes {
    let mut attrs = old_attrs.clone();
    attrs.unique_identifier = None;
    attrs.link = None;
    attrs.name = None;
    attrs.initial_date = None;
    attrs.last_change_date = None;
    attrs.activation_date = None;
    attrs.deactivation_date = None;
    attrs.destroy_date = None;
    attrs.compromise_date = None;
    attrs.compromise_occurrence_date = None;
    attrs.remove_vendor_attribute(vendor_id, "tag");
    attrs
}
