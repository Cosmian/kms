use abe_policy::{AccessPolicy, Policy};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, VendorAttribute},
    },
};

pub const VENDOR_ID_COSMIAN: &str = "cosmian";
pub const VENDOR_ATTR_ABE_ATTR: &str = "abe_attributes";
pub const VENDOR_ATTR_ABE_POLICY: &str = "abe_policy";
pub const VENDOR_ATTR_ABE_ACCESS_POLICY: &str = "abe_access_policy";
pub const VENDOR_ATTR_ABE_MASTER_PRIV_KEY_ID: &str = "abe_master_private_key_id";
pub const VENDOR_ATTR_ABE_MASTER_PUB_KEY_ID: &str = "abe_master_public_key_id";

/// Convert an policy to a vendor attribute
pub fn policy_as_vendor_attribute(policy: &Policy) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_ABE_POLICY.to_owned(),
        attribute_value: serde_json::to_vec(policy).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the ABE policy: {e}"),
            )
        })?,
    })
}

/// Extract an ABE policy from attributes
pub fn policy_from_attributes(attributes: &Attributes) -> Result<Policy, KmipError> {
    if let Some(bytes) = attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_POLICY)
    {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the ABE Policy from the attributes: {e}"),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain an ABE Policy".to_string(),
        ))
    }
}

/// Add or replace an ABE policy in attributes in place
pub fn upsert_policy_in_attributes(
    attributes: &mut Attributes,
    policy: &Policy,
) -> Result<(), KmipError> {
    let va = policy_as_vendor_attribute(policy)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert an access policy to a vendor attribute
pub fn access_policy_as_vendor_attribute(
    access_policy: &AccessPolicy,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_ABE_ACCESS_POLICY.to_owned(),
        attribute_value: serde_json::to_vec(access_policy).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the ABE access policy: {e}"),
            )
        })?,
    })
}

/// Convert from ABE policy attributes to vendor attributes
pub fn attributes_as_vendor_attribute(
    attributes: Vec<abe_policy::Attribute>,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_ABE_ATTR.to_owned(),
        attribute_value: serde_json::to_vec(&attributes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the ABE attributes: {e}"),
            )
        })?,
    })
}

/// Convert from vendor attributes to ABE policy attributes
pub fn attributes_from_attributes(
    attributes: &Attributes,
) -> Result<Vec<abe_policy::Attribute>, KmipError> {
    if let Some(bytes) = attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_ATTR) {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the ABE attributes from the attributes: {e}"),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain ABE (vendor) Attributes".to_string(),
        ))
    }
}

/// Extract an ABE Access policy from attributes
pub fn access_policy_from_attributes(attributes: &Attributes) -> Result<AccessPolicy, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_ACCESS_POLICY)
    {
        serde_json::from_slice(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the ABE Access Policy from the attributes {e}"),
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
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_ACCESS_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert an abe master private key id to a vendor attribute
pub fn master_private_key_id_as_vendor_attribute(
    abe_master_private_key_id: &str,
) -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_ABE_MASTER_PRIV_KEY_ID.to_owned(),
        attribute_value: abe_master_private_key_id.as_bytes().to_vec(),
    }
}

pub fn master_private_key_id_from_attributes(attributes: &Attributes) -> Result<&str, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_MASTER_PRIV_KEY_ID)
    {
        std::str::from_utf8(bytes).map_err(|_| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the ABE Master Private Key ID from the attributes"
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

/// Convert an abe master public key id to a vendor attribute
pub fn master_public_key_id_to_vendor_attribute(abe_master_public_key_id: &str) -> VendorAttribute {
    VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_ABE_MASTER_PUB_KEY_ID.to_owned(),
        attribute_value: abe_master_public_key_id.as_bytes().to_vec(),
    }
}

pub fn master_public_key_id_from_attributes(attributes: &Attributes) -> Result<&str, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_ABE_MASTER_PUB_KEY_ID)
    {
        std::str::from_utf8(bytes).map_err(|_| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing the ABE Master Public Key ID from the attributes".to_string(),
            )
        })
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain a Master Public Key ID".to_string(),
        ))
    }
}
