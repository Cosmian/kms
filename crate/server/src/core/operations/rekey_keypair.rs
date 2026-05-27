#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::cover_crypt::attributes::rekey_edit_action_from_attributes,
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::ObjectType,
            kmip_operations::{CreateKeyPair, ReKeyKeyPair, ReKeyKeyPairResponse},
            kmip_types::{KeyFormatType, LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::{info, trace};
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::rekey_keypair_cover_crypt;
use crate::{
    core::{
        KMS,
        operations::{
            create_key_pair::generate_key_pair,
            key_ops::{ObjectWithMetadataOps, setup_object_lifecycle},
            rekey_common::{prepare_replacement_attributes, update_old_key_after_rekey},
        },
        retrieve_object_utils::user_has_permission,
        wrapping::wrap_and_cache,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// KMIP `ReKeyKeyPair` operation for asymmetric key pairs.
///
/// Per KMIP 1.4 §4.5:
/// - Creates a replacement key pair with new Unique Identifiers.
/// - Sets `ReplacementObjectLink` on both old private and public keys.
/// - Sets `ReplacedObjectLink` on both new private and public keys.
/// - The replacement keys take over the Name attributes of the existing keys.
/// - The existing keys' State is NOT changed.
/// - If `offset` is provided, date arithmetic per Table 176 is applied.
///
/// For Covercrypt keys (non-FIPS only), delegates to the existing in-place
/// attribute-level rekey which mutates the key material without creating new UIDs.
pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &str,

    privileged_users: Option<Vec<String>>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("ReKeyKeyPair: {}", serde_json::to_string(&request)?);

    if request.common_protection_storage_masks.is_some()
        || request.private_protection_storage_masks.is_some()
        || request.public_protection_storage_masks.is_some()
    {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // ReKeyKeyPair creates a replacement key pair — enforce privileged-user restriction
    if let Some(ref users) = privileged_users {
        let has_permission = user_has_permission(user, None, &KmipOperation::Create, kms).await?;

        if !has_permission && !users.iter().any(|u| u == user) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    // there must be an identifier
    let uid_or_tags = request
        .private_key_unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ReKeyKeyPair: the private key unique identifier must be a string")?;

    let offset = request.offset;

    // retrieve from tags or use passed identifier
    let owm_s = kms
        .database
        .retrieve_objects(uid_or_tags)
        .await?
        .into_values();

    for owm in owm_s {
        // Only Active or PreActive objects are eligible for rekey
        if owm.state() != State::Active && owm.state() != State::PreActive {
            continue;
        }

        if owm.object().object_type() != ObjectType::PrivateKey {
            continue;
        }

        // Verify the caller is allowed to rekey this key pair
        if !owm
            .user_can_perform_operation(user, &KmipOperation::Rekey, kms)
            .await?
        {
            continue;
        }

        // Dispatch based on the existing key's format type
        let key_format_type = owm.attributes().key_format_type.or_else(|| {
            owm.object()
                .attributes()
                .ok()
                .and_then(|a| a.key_format_type)
        });

        // Covercrypt special case (non-FIPS only)
        #[cfg(feature = "non-fips")]
        if key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
            let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReKeyKeyPair: the private key attributes must be supplied for Covercrypt"
                        .to_owned(),
                )
            })?;
            if Some(CryptographicAlgorithm::CoverCrypt) == attributes.cryptographic_algorithm {
                let action = rekey_edit_action_from_attributes(kms.vendor_id(), attributes)?;
                return Box::pin(rekey_keypair_cover_crypt(
                    kms,
                    Covercrypt::default(),
                    owm.id().to_owned(),
                    user,
                    action,
                    owm.attributes().sensitive.unwrap_or(false),
                    privileged_users,
                ))
                .await
                .context("ReKeyKeyPair: Covercrypt rekey failed");
            }
        }

        // Skip Covercrypt keys in FIPS mode
        #[cfg(not(feature = "non-fips"))]
        if key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
            continue;
        }

        // ── General asymmetric key pair rekey (RSA, EC, PQC) ──

        // Reject wrapped keys
        if owm.object().key_wrapping_data().is_some() {
            kms_bail!(KmsError::InconsistentOperation(
                "The server cannot rekey: the private key is wrapped. Unwrap it first.".to_owned()
            ))
        }

        let old_sk_uid = owm.id().to_owned();

        // Follow PublicKeyLink to find the paired public key
        let old_pk_uid = owm
            .attributes()
            .get_link(LinkType::PublicKeyLink)
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReKeyKeyPair: the private key has no PublicKeyLink. Cannot determine the \
                     paired public key."
                        .to_owned(),
                )
            })?
            .to_string();

        // Retrieve the old public key
        let old_pk_owm = kms
            .database
            .retrieve_objects(&old_pk_uid)
            .await?
            .into_values()
            .next()
            .ok_or_else(|| {
                KmsError::Kmip21Error(
                    ErrorReason::Item_Not_Found,
                    format!("ReKeyKeyPair: linked public key '{old_pk_uid}' not found in database"),
                )
            })?;

        // Reject wrapped public keys too
        if old_pk_owm.object().key_wrapping_data().is_some() {
            kms_bail!(KmsError::InconsistentOperation(
                "The server cannot rekey: the public key is wrapped. Unwrap it first.".to_owned()
            ))
        }

        // Validate that the request doesn't try to change cryptographic parameters
        validate_no_crypto_param_change(owm.attributes(), &request)?;

        // Build a CreateKeyPair request from the existing key's attributes
        let mut common_attrs = owm.attributes().clone();
        // Clear fields that shouldn't be passed to key generation
        common_attrs.unique_identifier = None;
        common_attrs.link = None;
        common_attrs.name = None;
        common_attrs.initial_date = None;
        common_attrs.last_change_date = None;
        common_attrs.activation_date = None;
        common_attrs.deactivation_date = None;
        common_attrs.destroy_date = None;
        common_attrs.compromise_date = None;
        common_attrs.compromise_occurrence_date = None;
        // Remove vendor tag attribute (contains system tags like _sk/_pk)
        common_attrs.remove_vendor_attribute(kms.vendor_id(), "tag");

        let new_sk_uid = Uuid::new_v4().to_string();
        let new_pk_uid = Uuid::new_v4().to_string();

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

        // Prepare replacement attributes for both private and public keys
        let new_sk_attributes =
            prepare_replacement_attributes(owm.attributes(), &old_sk_uid, offset)?;
        let new_pk_attributes =
            prepare_replacement_attributes(old_pk_owm.attributes(), &old_pk_uid, offset)?;

        let sk_activation_date = new_sk_attributes.activation_date;
        let pk_activation_date = new_pk_attributes.activation_date;

        // Set up private key lifecycle
        let mut new_private_key = key_pair.private_key().to_owned();

        // Set the replacement attributes on the new private key's internal attributes
        if let Ok(sk_attrs) = new_private_key.attributes_mut() {
            sk_attrs.name.clone_from(&new_sk_attributes.name);
            sk_attrs.set_link(
                LinkType::ReplacedObjectLink,
                LinkedObjectIdentifier::TextString(old_sk_uid.clone()),
            );
            sk_attrs.set_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::TextString(new_pk_uid.clone()),
            );
        }

        let new_sk_obj_attributes = setup_object_lifecycle(
            &mut new_private_key,
            ObjectType::PrivateKey,
            sk_activation_date,
        )?;
        let sk_tags = new_sk_obj_attributes.get_tags(kms.vendor_id());

        Box::pin(wrap_and_cache(
            kms,
            user,
            &UniqueIdentifier::TextString(new_sk_uid.clone()),
            &mut new_private_key,
        ))
        .await?;

        // Set up public key lifecycle
        let mut new_public_key = key_pair.public_key().to_owned();

        // Set the replacement attributes on the new public key's internal attributes
        if let Ok(pk_attrs) = new_public_key.attributes_mut() {
            pk_attrs.name.clone_from(&new_pk_attributes.name);
            pk_attrs.set_link(
                LinkType::ReplacedObjectLink,
                LinkedObjectIdentifier::TextString(old_pk_uid.clone()),
            );
            pk_attrs.set_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::TextString(new_sk_uid.clone()),
            );
        }

        let new_pk_obj_attributes = setup_object_lifecycle(
            &mut new_public_key,
            ObjectType::PublicKey,
            pk_activation_date,
        )?;
        let pk_tags = new_pk_obj_attributes.get_tags(kms.vendor_id());

        Box::pin(wrap_and_cache(
            kms,
            user,
            &UniqueIdentifier::TextString(new_pk_uid.clone()),
            &mut new_public_key,
        ))
        .await?;

        // Update old private key
        let mut old_sk_object = owm.object().clone();
        let mut old_sk_attributes = owm.attributes().clone();
        update_old_key_after_rekey(&mut old_sk_attributes, &new_sk_uid)?;
        if let Ok(obj_attrs) = old_sk_object.attributes_mut() {
            update_old_key_after_rekey(obj_attrs, &new_sk_uid)?;
        }

        // Update old public key
        let mut old_pk_object = old_pk_owm.object().clone();
        let mut old_pk_attributes = old_pk_owm.attributes().clone();
        update_old_key_after_rekey(&mut old_pk_attributes, &new_pk_uid)?;
        if let Ok(obj_attrs) = old_pk_object.attributes_mut() {
            update_old_key_after_rekey(obj_attrs, &new_pk_uid)?;
        }

        // Execute all operations atomically:
        // 1. Create new private key
        // 2. Create new public key
        // 3. Update old private key
        // 4. Update old public key
        let operations = vec![
            AtomicOperation::Create((
                new_sk_uid.clone(),
                new_private_key,
                new_sk_obj_attributes,
                sk_tags,
            )),
            AtomicOperation::Create((
                new_pk_uid.clone(),
                new_public_key,
                new_pk_obj_attributes,
                pk_tags,
            )),
            AtomicOperation::UpdateObject((
                old_sk_uid.clone(),
                old_sk_object,
                old_sk_attributes,
                None,
            )),
            AtomicOperation::UpdateObject((
                old_pk_uid.clone(),
                old_pk_object,
                old_pk_attributes,
                None,
            )),
        ];

        kms.database.atomic(user, &operations).await?;

        info!(
            old_sk_uid = old_sk_uid,
            old_pk_uid = old_pk_uid,
            new_sk_uid = new_sk_uid,
            new_pk_uid = new_pk_uid,
            user = user,
            "Re-keyed key pair: new replacement keys created, old keys remain Active",
        );

        return Ok(ReKeyKeyPairResponse {
            private_key_unique_identifier: UniqueIdentifier::TextString(new_sk_uid),
            public_key_unique_identifier: UniqueIdentifier::TextString(new_pk_uid),
        });
    }

    Err(KmsError::Kmip21Error(
        ErrorReason::Item_Not_Found,
        uid_or_tags.to_owned(),
    ))
}

/// Validate that the `ReKeyKeyPair` request does not attempt to change cryptographic parameters.
///
/// Per KMIP 1.4 §4.5: "Attributes of the replacement key pair are copied from the existing
/// key pair." Changing algorithm, curve, or key length requires a new `CreateKeyPair` instead.
fn validate_no_crypto_param_change(
    existing_attrs: &cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
    request: &ReKeyKeyPair,
) -> KResult<()> {
    // Check all attribute sources in the request
    for req_attrs in [
        request.common_attributes.as_ref(),
        request.private_key_attributes.as_ref(),
        request.public_key_attributes.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(algo) = req_attrs.cryptographic_algorithm {
            if existing_attrs.cryptographic_algorithm != Some(algo) {
                kms_bail!(KmsError::InvalidRequest(
                    "ReKeyKeyPair: changing the cryptographic algorithm is not allowed. \
                     Use CreateKeyPair for a different algorithm."
                        .to_owned()
                ))
            }
        }
        if let Some(ref cdp) = req_attrs.cryptographic_domain_parameters {
            if let Some(ref existing_cdp) = existing_attrs.cryptographic_domain_parameters {
                if cdp.recommended_curve.is_some()
                    && cdp.recommended_curve != existing_cdp.recommended_curve
                {
                    kms_bail!(KmsError::InvalidRequest(
                        "ReKeyKeyPair: changing the recommended curve is not allowed. \
                         Use CreateKeyPair for a different curve."
                            .to_owned()
                    ))
                }
            }
        }
        if let Some(len) = req_attrs.cryptographic_length {
            if existing_attrs.cryptographic_length.is_some()
                && existing_attrs.cryptographic_length != Some(len)
            {
                kms_bail!(KmsError::InvalidRequest(
                    "ReKeyKeyPair: changing the cryptographic length is not allowed. \
                     Use CreateKeyPair for a different key size."
                        .to_owned()
                ))
            }
        }
    }
    Ok(())
}
