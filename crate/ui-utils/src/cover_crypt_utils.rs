use cloudproof::reexport::cover_crypt::abe_policy::Policy;
use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_objects::ObjectType,
    kmip_operations::CreateKeyPair,
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, VendorAttribute,
    },
};

use crate::error::UtilsError;

pub const VENDOR_ATTR_COVER_CRYPT_POLICY: &str = "cover_crypt_policy";

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
