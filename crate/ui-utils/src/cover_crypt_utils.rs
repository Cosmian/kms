use cloudproof::reexport::cover_crypt::abe_policy::Policy;
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

pub const VENDOR_ATTR_COVER_CRYPT_POLICY: &str = "cover_crypt_policy";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";

/// Convert an policy to a vendor attribute
pub fn policy_as_vendor_attribute(policy: &Policy) -> Result<VendorAttribute, UtilsError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_POLICY.to_owned(),
        attribute_value: Vec::<u8>::try_from(policy).map_err(|e| {
            UtilsError::Default(format!(
                "failed convert the CoverCrypt policy to bytes: {e}"
            ))
        })?,
    })
}

pub fn build_create_covercrypt_master_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    policy: &Policy,
    tags: T,
    sensitive: bool,
) -> Result<CreateKeyPair, UtilsError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![policy_as_vendor_attribute(policy)?]),
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

/// Convert an access policy to a vendor attribute
pub fn access_policy_as_vendor_attribute(
    access_policy: &str,
) -> Result<VendorAttribute, UtilsError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: access_policy.as_bytes().to_vec(),
    })
}

pub fn build_create_covercrypt_user_decryption_key_request<
    T: IntoIterator<Item = impl AsRef<str>>,
>(
    access_policy: &str,
    cover_crypt_master_private_key_id: &str,
    tags: T,
    sensitive: bool,
) -> Result<Create, UtilsError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_private_key_id.to_owned(),
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
