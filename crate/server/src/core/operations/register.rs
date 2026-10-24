use cosmian_kms_server_database::reexport::cosmian_kmip::{
    creation_time,
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{Register, RegisterResponse},
        kmip_types::UniqueIdentifier,
    },
    time_normalize,
};
use cosmian_logger::{debug, trace};

use super::import::process_opaque_object;
use crate::{
    core::{
        KMS,
        operations::import::{
            process_certificate, process_private_key, process_public_key, process_secret_data,
            process_symmetric_key,
        },
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

pub(crate) async fn register(
    kms: &KMS,
    mut request: Register,
    owner: &UserId,
) -> KResult<RegisterResponse> {
    trace!("Register request");
    KMS::reject_protection_storage_masks(request.protection_storage_masks.is_some())?;
    kms.enforce_create_permission(owner).await?;

    if request.object_type != request.object.object_type() {
        kms_bail!(KmsError::InconsistentOperation(
            "Specified object type does not match the type of object to register.".to_owned()
        ))
    }

    super::create::reject_inapplicable_attributes(
        "Register",
        request.object_type,
        &request.attributes,
    )?;
    if let Some(length) = request.attributes.cryptographic_length.filter(|l| *l <= 0) {
        kms_bail!(KmsError::Kmip21Error(
            ErrorReason::Invalid_Attribute_Value,
            format!("Register: invalid Cryptographic Length {length}")
        ));
    }

    // Update lifecycle: determine state based on ActivationDate per KMIP 2.1 spec.
    // Per KMIP 2.1 section 3.1.7 "Key States and Transitions":
    // - If ActivationDate is absent or in the future → PreActive state
    // - If ActivationDate is present and <= now → Active state
    let now = time_normalize()?;
    let activation_allows_active = request.attributes.activation_date.is_some_and(|d| d <= now);
    let desired_state = if activation_allows_active {
        debug!(
            "Register: activation_date={:?} <= now, setting state to Active",
            request.attributes.activation_date
        );
        State::Active
    } else {
        debug!("Register: no activation_date or future date, setting state to PreActive");
        State::PreActive
    };

    // Set the state in the request attributes (used by process_* functions)
    request.attributes.state = Some(desired_state);

    // KMIP 2.1 §6.1.43: the Initial Date of the registered object SHALL be the current time,
    // whatever the client supplied.
    let initial_date = creation_time()?;
    request.attributes.initial_date = Some(initial_date);

    // KMIP 2.1 §4.28: Key Value Present SHALL be created by the server (false) when the Key
    // Value is absent from the registered Key Block (the Key Value Location may say where it is).
    if request
        .object
        .key_block()
        .is_ok_and(|key_block| key_block.key_value.is_none())
    {
        request.attributes.key_value_present = Some(false);
    }

    // KMIP 2.1 §4.21: the server SHALL set the Digest of a registered object, here the SHA-256
    // of its Key Material as registered (wrapped Key Material is not digested).
    if request
        .object
        .key_block()
        .ok()
        .is_none_or(|key_block| key_block.key_wrapping_data.is_none())
    {
        request.attributes.digest = super::digest::registration_digests(&request.object)?;
    }
    // KMIP 2.1 §4.24: Fresh SHALL be True for a new object unless the client registers it False.
    request.attributes.fresh.get_or_insert(true);

    // Also set it in the object's attributes for consistency
    let now_stored = time_normalize()?;
    if let Ok(object_attributes) = request.object.attributes_mut() {
        object_attributes.state = Some(desired_state);
        object_attributes.initial_date = Some(initial_date);
        object_attributes.last_change_date = Some(now_stored);
    }

    // Process the request based on the object type,
    let (uid, operations) = match request.object.object_type() {
        ObjectType::SymmetricKey => {
            Box::pin(process_symmetric_key(kms, request.into(), owner)).await?
        }
        ObjectType::Certificate => process_certificate(kms.vendor_id(), request.into(), owner)?,
        ObjectType::PublicKey => Box::pin(process_public_key(kms, request.into(), owner)).await?,
        ObjectType::PrivateKey => Box::pin(process_private_key(kms, request.into(), owner)).await?,
        ObjectType::SecretData => Box::pin(process_secret_data(kms, request.into(), owner)).await?,
        ObjectType::OpaqueObject => {
            // Reuse the import path logic (no unwrap/wrap for opaque objects)
            let (uid, ops) = process_opaque_object(kms.vendor_id(), request.into(), owner)?;
            (uid, ops)
        }
        x => {
            return Err(KmsError::NotSupported(format!(
                "Register is not yet supported for objects of type : {x}"
            )));
        }
    };
    kms.constraints.check_new_objects(&operations)?;
    kms.database.atomic(owner, &operations).await?;
    debug!("Registered object with uid: {}", uid);
    Ok(RegisterResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

#[cfg(test)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{
            CryptographicUsageMask, ErrorReason, HashingAlgorithm, KeyValueLocation,
            KeyValueLocationType,
        },
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, SymmetricKey},
            kmip_operations::{Export, Get, GetAttributes, Register},
            kmip_types::{CryptographicAlgorithm, CryptographicParameters, Digest, KeyFormatType},
        },
    };
    use zeroize::Zeroizing;

    use crate::{
        error::KmsError, middlewares::UserId, result::KResult, tests::test_utils::test_kms,
    };

    /// KMIP 2.1 §4.27-§4.28 (TC-MDO-*): a key registered without its Key Value gets Key Value
    /// Present false, keeps its Key Value Location and is returned as registered by Get.
    #[tokio::test]
    async fn register_without_key_value() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("mdo-owner@example.com");
        let location = KeyValueLocation {
            key_value_location_value: "HSM-13345".to_owned(),
            key_value_location_type: KeyValueLocationType::UninterpretedTextString,
        };
        let uid = kms
            .register(
                Register {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(128),
                        key_value_location: Some(location.clone()),
                        ..Attributes::default()
                    },
                    object: Object::SymmetricKey(SymmetricKey {
                        key_block: KeyBlock {
                            key_format_type: KeyFormatType::Raw,
                            key_compression_type: None,
                            key_value: None,
                            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                            cryptographic_length: Some(128),
                            key_wrapping_data: None,
                        },
                    }),
                    protection_storage_masks: None,
                },
                &owner,
            )
            .await?
            .unique_identifier;

        let attributes = kms
            .get_attributes(GetAttributes::from(uid.to_string()), &owner)
            .await?
            .attributes;

        let got = kms
            .get(Get::new(uid.clone(), false, None, None), &owner)
            .await?;
        let returned_as_registered = got.object.key_block()?.key_value.is_none();

        let converted = kms
            .get(
                Get::new(
                    uid,
                    false,
                    None,
                    Some(KeyFormatType::TransparentSymmetricKey),
                ),
                &owner,
            )
            .await;
        if attributes.key_value_present != Some(false)
            || attributes.key_value_location != Some(location)
            || !returned_as_registered
            || !matches!(
                converted,
                Err(KmsError::Kmip21Error(ErrorReason::Key_Value_Not_Present, _))
            )
        {
            return Err(KmsError::Default(format!(
                "metadata-only key mishandled: {attributes:?}, as registered: \
                 {returned_as_registered}, converted Get: {:?}",
                converted.err()
            )));
        }
        Ok(())
    }

    /// KMIP 2.1 §4.21 / §4.24 / §6.1.18 (TC-IMPEXP-1-20): Register sets the Digest (SHA-256 of
    /// the Key Material in the default Raw format) and Fresh true; Export returns the attributes
    /// Get Attributes reports, as they were before the key was served.
    #[tokio::test]
    async fn register_sets_digest_and_fresh_and_export_returns_them() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("impexp-owner@example.com");
        let key = vec![0x5a_u8; 16];
        let uid = kms
            .register(
                Register {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(128),
                        ..Attributes::default()
                    },
                    object: Object::SymmetricKey(SymmetricKey {
                        key_block: KeyBlock {
                            key_format_type: KeyFormatType::Raw,
                            key_compression_type: None,
                            key_value: Some(KeyValue::Structure {
                                key_material: KeyMaterial::ByteString(Zeroizing::new(key.clone())),
                                attributes: None,
                            }),
                            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                            cryptographic_length: Some(128),
                            key_wrapping_data: None,
                        },
                    }),
                    protection_storage_masks: None,
                },
                &owner,
            )
            .await?
            .unique_identifier;
        let expected_digest = Digest {
            hashing_algorithm: HashingAlgorithm::SHA256,
            digest_value: Some(openssl::sha::sha256(&key).to_vec()),
            key_format_type: Some(KeyFormatType::Raw),
        };

        let before = kms
            .get_attributes(GetAttributes::from(uid.to_string()), &owner)
            .await?
            .attributes;
        let mut exported = kms
            .export(
                Export {
                    unique_identifier: Some(uid.clone()),
                    ..Export::default()
                },
                &owner,
            )
            .await?
            .attributes;
        // Export also carries the tags, which Get Attributes leaves out unless asked for.
        let has_tags = exported.remove_tags(kms.vendor_id()).is_some();
        let after = kms
            .get_attributes(GetAttributes::from(uid.to_string()), &owner)
            .await?
            .attributes;
        if before.digest != Some(vec![expected_digest])
            || before.fresh != Some(true)
            || !has_tags
            || exported != before
            || after.fresh != Some(false)
        {
            return Err(KmsError::Default(format!(
                "before export: {before:?}, exported: {exported:?}, after: {after:?}"
            )));
        }
        Ok(())
    }

    /// A key registered without its Key Value (Key Value Present false) is no key material: the
    /// operations that read key bytes must refuse it, none may treat it as an empty key.
    #[tokio::test]
    async fn valueless_key_is_refused_by_key_consuming_operations() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
            Activate, Encrypt, MAC,
        };
        use zeroize::Zeroizing;

        let kms = test_kms().await?;
        let owner = UserId::from("mdo-negative@example.com");
        let uid = kms
            .register(
                Register {
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_length: Some(128),
                        cryptographic_usage_mask: Some(
                            CryptographicUsageMask::Encrypt
                                | CryptographicUsageMask::Decrypt
                                | CryptographicUsageMask::MACGenerate
                                | CryptographicUsageMask::DeriveKey,
                        ),
                        ..Attributes::default()
                    },
                    object: Object::SymmetricKey(SymmetricKey {
                        key_block: KeyBlock {
                            key_format_type: KeyFormatType::Raw,
                            key_compression_type: None,
                            key_value: None,
                            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                            cryptographic_length: Some(128),
                            key_wrapping_data: None,
                        },
                    }),
                    protection_storage_masks: None,
                },
                &owner,
            )
            .await?
            .unique_identifier;
        kms.activate(
            Activate {
                unique_identifier: uid.clone(),
            },
            &owner,
        )
        .await?;

        let encrypt = kms
            .encrypt(
                Encrypt {
                    unique_identifier: Some(uid.clone()),
                    data: Some(Zeroizing::new(b"secret".to_vec())),
                    ..Encrypt::default()
                },
                &owner,
            )
            .await;
        let mac = kms
            .mac(
                MAC {
                    unique_identifier: Some(uid.clone()),
                    cryptographic_parameters: Some(CryptographicParameters {
                        hashing_algorithm: Some(HashingAlgorithm::SHA256),
                        ..CryptographicParameters::default()
                    }),
                    data: Some(b"data".to_vec()),
                    ..MAC::default()
                },
                &owner,
            )
            .await;
        let export_converted = kms
            .export(
                Export {
                    unique_identifier: Some(uid.clone()),
                    key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                    ..Export::default()
                },
                &owner,
            )
            .await;
        for (name, result) in [
            ("encrypt", encrypt.map(|_| ())),
            ("mac", mac.map(|_| ())),
            ("export converted", export_converted.map(|_| ())),
        ] {
            if result.is_ok() {
                return Err(KmsError::Default(format!(
                    "{name} accepted a key registered without its Key Value"
                )));
            }
        }
        Ok(())
    }
}
