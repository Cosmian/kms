use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateKeyPair},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier, VendorAttribute,
    },
};

use crate::error::UtilsError;
pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE: &str = "cover_crypt_access_structure";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION: &str = "cover_crypt_rekey_action";

/// Build a `CreateKeyPair` request for an `CoverCrypt` Master Key
pub fn build_create_covercrypt_master_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_structure: &str,
    tags: T,
    sensitive: bool,
) -> Result<CreateKeyPair, UtilsError> {
    let vendor_attributes = VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE.to_owned(),
        attribute_value: access_structure.as_bytes().to_vec(),
    };
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![vendor_attributes]),
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
) -> Result<Create, UtilsError> {
    let vendor_attributes: VendorAttribute = VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: access_policy.as_bytes().to_vec(),
    };
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![vendor_attributes]),
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
