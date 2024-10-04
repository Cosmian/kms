use cloudproof::reexport::cover_crypt::abe_policy::{self, AccessPolicy, EncryptionHint, Policy};
use serde::{Deserialize, Serialize};

use crate::{
    error::KmipError,
    kmip::{
        extra::VENDOR_ID_COSMIAN,
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, VendorAttribute},
    },
};

pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_POLICY: &str = "cover_crypt_policy";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION: &str = "cover_crypt_rekey_action";

/// Convert an policy to a vendor attribute
pub fn policy_as_vendor_attribute(policy: &Policy) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_POLICY.to_owned(),
        attribute_value: Vec::<u8>::try_from(policy).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed convert the CoverCrypt policy to bytes: {e}"),
            )
        })?,
    })
}

/// Extract an `CoverCrypt` policy from attributes
pub fn policy_from_attributes(attributes: &Attributes) -> Result<Policy, KmipError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_POLICY)
        .map_or_else(
            || {
                Err(KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    "the attributes do not contain a CoverCrypt Policy".to_owned(),
                ))
            },
            |bytes| {
                Policy::parse_and_convert(bytes).map_err(|e| {
                    KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Attribute_Value,
                        format!(
                            "failed deserializing the CoverCrypt Policy from the attributes: {e}"
                        ),
                    )
                })
            },
        )
}

/// Add or replace an `CoverCrypt` policy in attributes in place
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
    access_policy: &str,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: access_policy.as_bytes().to_vec(),
    })
}

/// Convert from `CoverCrypt` policy attributes to vendor attributes
pub fn attributes_as_vendor_attribute(
    attributes: &[abe_policy::Attribute],
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

/// Convert from vendor attributes to `CoverCrypt` policy attributes
pub fn attributes_from_attributes(
    attributes: &Attributes,
) -> Result<Vec<abe_policy::Attribute>, KmipError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ATTR)
    {
        let attribute_strings = serde_json::from_slice::<Vec<String>>(bytes).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!(
                    "failed reading the CoverCrypt attribute strings from the attributes bytes: \
                     {e}"
                ),
            )
        })?;
        let mut policy_attributes = Vec::with_capacity(attribute_strings.len());
        for attr in attribute_strings {
            let attr = abe_policy::Attribute::try_from(attr.as_str()).map_err(|e| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    format!("failed deserializing the CoverCrypt attribute: {e}"),
                )
            })?;
            policy_attributes.push(attr);
        }
        Ok(policy_attributes)
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            "the attributes do not contain CoverCrypt (vendor) Attributes".to_owned(),
        ))
    }
}

/// Extract an `CoverCrypt` Access policy from attributes
pub fn access_policy_from_attributes(attributes: &Attributes) -> Result<String, KmipError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY)
        .map_or_else(
            || {
                Err(KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    "the attributes do not contain an Access Policy".to_owned(),
                ))
            },
            |bytes| {
                String::from_utf8(bytes.to_vec()).map_err(|e| {
                    KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Attribute_Value,
                        format!(
                            "failed to read Access Policy string from the (vendor) attributes \
                             bytes: {e}"
                        ),
                    )
                })
            },
        )
}

/// Add or replace an access policy in attributes in place
pub fn upsert_access_policy_in_attributes(
    attributes: &mut Attributes,
    access_policy: &str,
) -> Result<(), KmipError> {
    let va = access_policy_as_vendor_attribute(access_policy)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

pub fn deserialize_access_policy(ap: &str) -> Result<AccessPolicy, KmipError> {
    AccessPolicy::from_boolean_expression(ap).map_err(|e| {
        KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            format!("failed to deserialize the given Access Policy string: {e}"),
        )
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RekeyEditAction {
    RekeyAccessPolicy(String),
    PruneAccessPolicy(String),
    RemoveAttribute(Vec<abe_policy::Attribute>),
    DisableAttribute(Vec<abe_policy::Attribute>),
    AddAttribute(Vec<(abe_policy::Attribute, EncryptionHint)>),
    RenameAttribute(Vec<(abe_policy::Attribute, String)>),
}

/// Convert an edit action to a vendor attribute
pub fn rekey_edit_action_as_vendor_attribute(
    action: &RekeyEditAction,
) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION.to_owned(),
        attribute_value: serde_json::to_vec(action).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed serializing the CoverCrypt action: {e}"),
            )
        })?,
    })
}

/// Extract an edit `CoverCrypt` policy action from attributes.
///
/// If Covercrypt attributes are specified without an `EditPolicyAction`,
/// a `RotateAttributes` action is returned by default to keep backward compatibility.
pub fn rekey_edit_action_from_attributes(
    attributes: &Attributes,
) -> Result<RekeyEditAction, KmipError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION)
        .map_or_else(
            || {
                Err(KmipError::InvalidKmipObject(
                    ErrorReason::Missing_Data,
                    "Missing VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION".to_owned(),
                ))
            },
            |bytes| {
                serde_json::from_slice::<RekeyEditAction>(bytes).map_err(|e| {
                    KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Attribute_Value,
                        format!(
                            "failed reading the CoverCrypt action from the attribute bytes: {e}"
                        ),
                    )
                })
            },
        )
}
