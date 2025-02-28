use cosmian_cover_crypt::{AccessPolicy, EncryptionHint, QualifiedAttribute};
use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_types::{Attributes, VendorAttribute},
};
use serde::{Deserialize, Serialize};

use super::master_keys::AccessStructure;
use crate::error::CryptoError;

pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_POLICY: &str = "cover_crypt_policy";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION: &str = "cover_crypt_rekey_action";

/// Convert an policy to a vendor attribute
pub fn policy_as_vendor_attribute(policy: &AccessStructure) -> Result<VendorAttribute, CryptoError> {
    let access_struc = serde_json::to_vec(&policy)?;
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_POLICY.to_owned(),
        attribute_value: access_struc,
    })
}

/// Extract an `CoverCrypt` policy from attributes
pub fn policy_from_attributes(attributes: &Attributes) -> Result<AccessStructure, CryptoError> {
    println!("ATTRIBUTE 1 : {attributes:?}");
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_POLICY)
        .map_or_else(
            || {
                Err(CryptoError::Kmip(
                    "the attributes do not contain a CoverCrypt Policy".to_owned(),
                ))
            },
            |bytes| {
                serde_json::from_slice(bytes).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed deserializing the CoverCrypt Policy from the attributes: {e}"
                    ))
                })
            },
        )
}

/// Add or replace an `CoverCrypt` policy in attributes in place
pub fn upsert_policy_in_attributes(
    attributes: &mut Attributes,
    policy: &AccessStructure,
) -> Result<(), CryptoError> {
    let va = policy_as_vendor_attribute(policy)?;
    println!("ATTRIBUTES 2 {va}");
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert from `CoverCrypt` policy attributes to vendor attributes
pub fn attributes_as_vendor_attribute(
    attributes: &[QualifiedAttribute],
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ATTR.to_owned(),
        attribute_value: serde_json::to_vec(&attributes).map_err(|e| {
            CryptoError::Kmip(format!("failed serializing the CoverCrypt attributes: {e}"))
        })?,
    })
}

/// Convert from vendor attributes to `CoverCrypt` policy attributes
pub fn attributes_from_attributes(
    attributes: &Attributes,
) -> Result<Vec<QualifiedAttribute>, CryptoError> {
    if let Some(bytes) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ATTR)
    {
        let attribute_strings = serde_json::from_slice::<Vec<String>>(bytes).map_err(|e| {
            CryptoError::Kmip(format!(
                "failed reading the CoverCrypt attribute strings from the attributes bytes: {e}"
            ))
        })?;
        let mut policy_attributes = Vec::with_capacity(attribute_strings.len());
        for attr in attribute_strings {
            let attr = QualifiedAttribute::try_from(attr.as_str()).map_err(|e| {
                CryptoError::Kmip(format!(
                    "failed deserializing the CoverCrypt attribute: {e}"
                ))
            })?;
            policy_attributes.push(attr);
        }
        Ok(policy_attributes)
    } else {
        Err(CryptoError::Kmip(
            "the attributes do not contain CoverCrypt (vendor) Attributes".to_owned(),
        ))
    }
}

/// Convert an access policy to a vendor attribute
pub fn access_policy_as_vendor_attribute(
    access_policy: &str,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: access_policy.as_bytes().to_vec(),
    })
}

/// Extract an `CoverCrypt` Access policy from attributes
pub fn access_policy_from_attributes(attributes: &Attributes) -> Result<String, CryptoError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY)
        .map_or_else(
            || {
                Err(CryptoError::Kmip(
                    "the attributes do not contain an Access Policy".to_owned(),
                ))
            },
            |bytes| {
                String::from_utf8(bytes.to_vec()).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed to read Access Policy string from the (vendor) attributes bytes: \
                         {e}"
                    ))
                })
            },
        )
}

/// Add or replace an access policy in attributes in place
pub fn upsert_access_policy_in_attributes(
    attributes: &mut Attributes,
    access_policy: &str,
) -> Result<(), CryptoError> {
    let va = access_policy_as_vendor_attribute(access_policy)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY);
    attributes.add_vendor_attribute(va);
    Ok(())
}

pub fn deserialize_access_policy(ap: &str) -> Result<AccessPolicy, CryptoError> {
    AccessPolicy::parse(ap).map_err(|e| {
        CryptoError::Kmip(format!(
            "failed to deserialize the given Access Policy string: {e}"
        ))
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RekeyEditAction {
    RekeyAccessPolicy(String),
    PruneAccessPolicy(String),
    DeleteAttribute(Vec<QualifiedAttribute>),
    DisableAttribute(Vec<QualifiedAttribute>),
    AddAttribute(Vec<(QualifiedAttribute, EncryptionHint, Option<String>)>),
    RenameAttribute(Vec<(QualifiedAttribute, String)>),
}

/// Convert an edit action to a vendor attribute
pub fn rekey_edit_action_as_vendor_attribute(
    action: &RekeyEditAction,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION.to_owned(),
        attribute_value: serde_json::to_vec(action).map_err(|e| {
            CryptoError::Kmip(format!("failed serializing the CoverCrypt action: {e}"))
        })?,
    })
}

/// Extract an edit `CoverCrypt` policy action from attributes.
///
/// If Covercrypt attributes are specified without an `EditPolicyAction`,
/// a `RotateAttributes` action is returned by default to keep backward compatibility.
pub fn rekey_edit_action_from_attributes(
    attributes: &Attributes,
) -> Result<RekeyEditAction, CryptoError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION)
        .map_or_else(
            || {
                Err(CryptoError::Kmip(
                    "Missing VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION".to_owned(),
                ))
            },
            |bytes| {
                serde_json::from_slice::<RekeyEditAction>(bytes).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed reading the CoverCrypt action from the attribute bytes: {e}"
                    ))
                })
            },
        )
}
