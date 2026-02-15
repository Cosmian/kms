use cosmian_cover_crypt::{AccessStructure, EncryptionHint, QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_attributes::Attributes,
    kmip_types::{VendorAttribute, VendorAttributeValue},
};
use serde::{Deserialize, Serialize};

use super::access_structure::access_structure_from_str;
use crate::{
    crypto::{
        VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE,
        VENDOR_ATTR_COVER_CRYPT_ATTR, VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION,
    },
    error::CryptoError,
};

/// Convert an access structure to a vendor attribute
pub fn access_structure_as_vendor_attribute(
    access_structure: &AccessStructure,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(
            access_structure
                .serialize()
                .map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed convert the Covercrypt access structure to bytes: {e}"
                    ))
                })?
                .to_vec(),
        ),
    })
}

/// Extract an `Covercrypt` access structure from attributes
pub fn access_structure_from_attributes(
    attributes: &Attributes,
) -> Result<AccessStructure, CryptoError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE)
        .map_or_else(
            || {
                Err(CryptoError::Kmip(
                    "the attributes do not contain a Covercrypt access structure".to_owned(),
                ))
            },
            |bytes| {
                let VendorAttributeValue::ByteString(bytes) = bytes else {
                    return Err(CryptoError::Kmip(
                        "the Covercrypt access structure is not a byte string".to_owned(),
                    ));
                };
                access_structure_from_str(std::str::from_utf8(bytes)?)
            },
        )
}

/// Add or replace an access policy in attributes in place
pub fn upsert_access_structure_in_attributes(
    attributes: &mut Attributes,
    access_structure: &AccessStructure,
) -> Result<(), CryptoError> {
    let va = access_structure_as_vendor_attribute(access_structure)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert a list of `Covercrypt` qualified attributes to a vendor attribute.
pub fn qualified_attributes_as_vendor_attributes(
    attributes: &[QualifiedAttribute],
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ATTR.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(
            serde_json::to_vec(&attributes).map_err(|e| {
                CryptoError::Kmip(format!("failed serializing the Covercrypt attributes: {e}"))
            })?,
        ),
    })
}

/// Extract qualified attributes from the given KMIP attributes.
pub fn qualified_attributes_from_attributes(
    attributes: &Attributes,
) -> Result<Vec<QualifiedAttribute>, CryptoError> {
    let bytes = attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ATTR)
        .ok_or_else(|| {
            CryptoError::Kmip(
                "the attributes do not contain Covercrypt (vendor) Attributes".to_owned(),
            )
        })?;
    let VendorAttributeValue::ByteString(bytes) = bytes else {
        return Err(CryptoError::Kmip(
            "the Covercrypt attributes are not a byte string".to_owned(),
        ));
    };
    let attribute_strings = serde_json::from_slice::<Vec<String>>(bytes).map_err(|e| {
        CryptoError::Kmip(format!(
            "failed reading the Covercrypt attribute strings from the attributes bytes: {e}"
        ))
    })?;
    attribute_strings
        .iter()
        .map(|attr| {
            QualifiedAttribute::try_from(attr.as_str()).map_err(|e| {
                CryptoError::Kmip(format!(
                    "failed deserializing the Covercrypt attribute: {e}"
                ))
            })
        })
        .collect()
}

/// Convert an access policy to a vendor attribute
pub fn access_policy_as_vendor_attribute(
    access_policy: &str,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(access_policy.as_bytes().to_vec()),
    })
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
        attribute_value: VendorAttributeValue::ByteString(serde_json::to_vec(action).map_err(
            |e| CryptoError::Kmip(format!("failed serializing the Covercrypt action: {e}")),
        )?),
    })
}

/// Extract an edit `Covercrypt` re-key action from attributes.
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
                let VendorAttributeValue::ByteString(bytes) = bytes else {
                    return Err(CryptoError::Kmip(
                        "the Covercrypt re-key action is not a byte string".to_owned(),
                    ));
                };
                serde_json::from_slice::<RekeyEditAction>(bytes).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed reading the Covercrypt action from the attribute bytes: {e}"
                    ))
                })
            },
        )
}
