use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, VendorAttribute},
    },
};
use cover_crypt::policies::{AccessPolicy, Policy};

pub const VENDOR_ID_COSMIAN: &str = "cosmian";
pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_POLICY: &str = "cover_crypt_policy";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_HEADER_UID: &str = "cover_crypt_header_uid";
pub const VENDOR_ATTR_COVER_CRYPT_MASTER_PRIV_KEY_ID: &str = "cover_crypt_master_private_key_id";
pub const VENDOR_ATTR_COVER_CRYPT_MASTER_PUB_KEY_ID: &str = "cover_crypt_master_public_key_id";

/// Convert an policy to a vendor attribute
pub fn policy_as_vendor_attribute(policy: &Policy) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_POLICY.to_owned(),
        attribute_value: serde_json::to_vec(policy).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the CoverCrypt policy: {e}"),
            )
        })?,
    })
}

/// Extract an CoverCrypt policy from attributes
pub fn policy_from_attributes(attributes: &Attributes) -> Result<Policy, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_POLICY)
    {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the CoverCrypt Policy from the attributes: {e}"),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain an CoverCrypt Policy".to_string(),
        ))
    }
}

/// Add or replace an CoverCrypt policy in attributes in place
pub fn upsert_policy_in_attributes(
    attributes: &mut Attributes,
    policy: &Policy,
) -> Result<(), KmipError> {
    let va = policy_as_vendor_attribute(policy)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert an access policy to a vendor attribute
pub fn access_policy_as_vendor_attribute(
    access_policy: &AccessPolicy,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: serde_json::to_vec(access_policy).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the CoverCrypt access policy: {e}"),
            )
        })?,
    })
}

/// Convert from CoverCrypt policy attributes to vendor attributes
pub fn attributes_as_vendor_attribute(
    attributes: Vec<cover_crypt::policies::Attribute>,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ATTR.to_owned(),
        attribute_value: serde_json::to_vec(&attributes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the CoverCrypt attributes: {e}"),
            )
        })?,
    })
}

/// Convert from vendor attributes to CoverCrypt policy attributes
pub fn attributes_from_attributes(
    attributes: &Attributes,
) -> Result<Vec<cover_crypt::policies::Attribute>, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ATTR)
    {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the CoverCrypt attributes from the attributes: {e}"),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain CoverCrypt (vendor) Attributes".to_string(),
        ))
    }
}

/// Extract an CoverCrypt Access policy from attributes
pub fn access_policy_from_attributes(attributes: &Attributes) -> Result<AccessPolicy, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY)
    {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!(
                    "failed deserializing the CoverCrypt Access Policy from the attributes {e}"
                ),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain an Access Policy".to_string(),
        ))
    }
}

/// Add or replace an access policy in attributes in place
pub fn upsert_access_policy_in_attributes(
    attributes: &mut Attributes,
    access_policy: &AccessPolicy,
) -> Result<(), KmipError> {
    let va = access_policy_as_vendor_attribute(access_policy)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert an cover_crypt master private key id to a vendor attribute
pub fn master_private_key_id_as_vendor_attribute(
    cover_crypt_master_private_key_id: &str,
) -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_MASTER_PRIV_KEY_ID.to_owned(),
        attribute_value: cover_crypt_master_private_key_id.as_bytes().to_vec(),
    }
}

pub fn master_private_key_id_from_attributes(attributes: &Attributes) -> Result<&str, KmipError> {
    if let Some(bytes) = attributes.get_vendor_attribute(
        VENDOR_ID_COSMIAN,
        VENDOR_ATTR_COVER_CRYPT_MASTER_PRIV_KEY_ID,
    ) {
        std::str::from_utf8(bytes).map_err(|_| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the CoverCrypt Master Private Key ID from the attributes"
                    .to_string(),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain a Master Private Key ID".to_string(),
        ))
    }
}

/// Convert an cover_crypt master public key id to a vendor attribute
pub fn master_public_key_id_to_vendor_attribute(
    cover_crypt_master_public_key_id: &str,
) -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_MASTER_PUB_KEY_ID.to_owned(),
        attribute_value: cover_crypt_master_public_key_id.as_bytes().to_vec(),
    }
}

pub fn master_public_key_id_from_attributes(attributes: &Attributes) -> Result<&str, KmipError> {
    if let Some(bytes) = attributes
        .get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_MASTER_PUB_KEY_ID)
    {
        std::str::from_utf8(bytes).map_err(|_| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the CoverCrypt Master Public Key ID from the attributes"
                    .to_string(),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain a Master Public Key ID".to_string(),
        ))
    }
}

/// This UID is used to build the asymmetric CoverCrypt Header object
pub fn header_uid_to_vendor_attribute(uid: &[u8]) -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_HEADER_UID.to_owned(),
        attribute_value: uid.to_vec(),
    }
}

pub fn header_uid_from_attributes(attributes: &Attributes) -> Result<&[u8], KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_HEADER_UID)
    {
        Ok(bytes)
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain an CoverCrypt Header UID".to_string(),
        ))
    }
}

//TODO: BGR: this seems unused - must be revisited _ see issue #192
// /// This UID is used to build the asymmetric CoverCrypt Header object
// #[cfg(test)]
// #[allow(deprecated)]
// pub fn cover_crypt_header_uid_to_vendor_attribute(uid: &[u8]) -> VendorAttribute {
//     VendorAttribute {
//         vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
//         attribute_name: VENDOR_ATTR_COVER_CRYPT_HEADER_UID.to_owned(),
//         attribute_value: uid.to_vec(),
//     }
// }
