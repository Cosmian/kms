use cosmian_cover_crypt::AccessStructure;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateKeyPair, Destroy, ReKeyKeyPair},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier, UniqueIdentifier,
    },
};

use super::attributes::{
    access_policy_as_vendor_attribute, access_structure_as_vendor_attribute,
    rekey_edit_action_as_vendor_attribute, RekeyEditAction,
};
use crate::error::CryptoError;

/// Build a `CreateKeyPair` request for an `CoverCrypt` Master Key
pub fn build_create_covercrypt_master_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_structure: &AccessStructure,
    tags: T,
    sensitive: bool,
) -> Result<CreateKeyPair, CryptoError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![access_structure_as_vendor_attribute(
            access_structure,
        )?]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        sensitive,
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(CreateKeyPair {
        common_attributes: Some(attributes),
        ..CreateKeyPair::default()
    })
}

/// Build a `Create` request for a `CoverCrypt` USK
pub fn build_create_covercrypt_usk_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_policy: &str,
    cover_crypt_master_secret_key_id: &str,
    tags: T,
    sensitive: bool,
) -> Result<Create, CryptoError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_secret_key_id.to_owned(),
            ),
        }]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        sensitive,
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(Create {
        attributes,
        object_type: ObjectType::PrivateKey,
        protection_storage_masks: None,
    })
}

/// Build a `Destroy` request to destroy an `CoverCrypt` User Decryption Key
pub fn build_destroy_key_request(unique_identifier: &str) -> Result<Destroy, CryptoError> {
    Ok(Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
        remove: false,
    })
}

/// Build a `ReKeyKeyPair` request.
/// To re-key an attribute of a user decryption key, we first need:
/// - the MSK UID
/// - the `CoverCrypt` attributes to revoke
/// - the `ReKeyKeyPairAction` to perform
///
/// The routine will then locate and renew all user decryption keys linked to
/// this MSK.
pub fn build_rekey_keypair_request(
    msk_uid: &str,
    action: &RekeyEditAction,
) -> Result<ReKeyKeyPair, CryptoError> {
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(msk_uid.to_owned())),
        private_key_attributes: Some(Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            vendor_attributes: Some(vec![rekey_edit_action_as_vendor_attribute(action)?]),
            ..Attributes::default()
        }),
        ..ReKeyKeyPair::default()
    })
}
