use cosmian_cover_crypt::{AccessStructure, EncryptionHint, QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
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
    vendor_id: &str,
    access_structure: &AccessStructure,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
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
    vendor_id: &str,
    attributes: &Attributes,
) -> Result<AccessStructure, CryptoError> {
    attributes
        .get_vendor_attribute_value(vendor_id, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE)
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
    vendor_id: &str,
    attributes: &mut Attributes,
    access_structure: &AccessStructure,
) -> Result<(), CryptoError> {
    let va = access_structure_as_vendor_attribute(vendor_id, access_structure)?;
    attributes.remove_vendor_attribute(vendor_id, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE);
    attributes.add_vendor_attribute(va);
    Ok(())
}

/// Convert a list of `Covercrypt` qualified attributes to a vendor attribute.
pub fn qualified_attributes_as_vendor_attributes(
    vendor_id: &str,
    attributes: &[QualifiedAttribute],
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
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
    vendor_id: &str,
    attributes: &Attributes,
) -> Result<Vec<QualifiedAttribute>, CryptoError> {
    let bytes = attributes
        .get_vendor_attribute_value(vendor_id, VENDOR_ATTR_COVER_CRYPT_ATTR)
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
    vendor_id: &str,
    access_policy: &str,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(access_policy.as_bytes().to_vec()),
    })
}

/// Add or replace an access policy in attributes in place
pub fn upsert_access_policy_in_attributes(
    vendor_id: &str,
    attributes: &mut Attributes,
    access_policy: &str,
) -> Result<(), CryptoError> {
    let va = access_policy_as_vendor_attribute(vendor_id, access_policy)?;
    attributes.remove_vendor_attribute(vendor_id, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY);
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
    AddAnarchy(String, Vec<(QualifiedAttribute, EncryptionHint)>),
    AddHierarchy(String, Vec<(QualifiedAttribute, EncryptionHint)>),
}

/// Convert an edit action to a vendor attribute
pub fn rekey_edit_action_as_vendor_attribute(
    vendor_id: &str,
    action: &RekeyEditAction,
) -> Result<VendorAttribute, CryptoError> {
    Ok(VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
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
    vendor_id: &str,
    attributes: &Attributes,
) -> Result<RekeyEditAction, CryptoError> {
    attributes
        .get_vendor_attribute_value(vendor_id, VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use cosmian_cover_crypt::{EncryptionHint, QualifiedAttribute};
    use cosmian_kms_client_utils::cover_crypt_utils::{
        CoverCryptEncryptionHint, CoverCryptRekeyAction, build_covercrypt_rekey_keypair_request,
    };

    use super::{RekeyEditAction, rekey_edit_action_from_attributes};
    use crate::crypto::cover_crypt::kmip_requests::build_rekey_keypair_request;

    const VENDOR: &str = "cosmian";

    fn hint(hint: EncryptionHint) -> CoverCryptEncryptionHint {
        match hint {
            EncryptionHint::Classic => CoverCryptEncryptionHint::Classic,
            EncryptionHint::PostQuantum => CoverCryptEncryptionHint::PostQuantum,
            EncryptionHint::Hybridized => CoverCryptEncryptionHint::Hybridized,
        }
    }

    /// The client-side mirror (`cosmian_kms_client_utils`, usable from WASM) of each
    /// server-side action. Exhaustive on purpose: a new `RekeyEditAction` variant doesn't
    /// compile until the mirror gets it too.
    fn mirror(action: &RekeyEditAction) -> CoverCryptRekeyAction {
        let attr = |a: &QualifiedAttribute| a.to_string();
        match action {
            RekeyEditAction::RekeyAccessPolicy(ap) => {
                CoverCryptRekeyAction::RekeyAccessPolicy(ap.clone())
            }
            RekeyEditAction::PruneAccessPolicy(ap) => {
                CoverCryptRekeyAction::PruneAccessPolicy(ap.clone())
            }
            RekeyEditAction::DeleteAttribute(attrs) => {
                CoverCryptRekeyAction::DeleteAttribute(attrs.iter().map(attr).collect())
            }
            RekeyEditAction::DisableAttribute(attrs) => {
                CoverCryptRekeyAction::DisableAttribute(attrs.iter().map(attr).collect())
            }
            RekeyEditAction::AddAttribute(attrs) => CoverCryptRekeyAction::AddAttribute(
                attrs
                    .iter()
                    .map(|(a, h, after)| (attr(a), hint(*h), after.clone()))
                    .collect(),
            ),
            RekeyEditAction::RenameAttribute(attrs) => CoverCryptRekeyAction::RenameAttribute(
                attrs
                    .iter()
                    .map(|(a, name)| (attr(a), name.clone()))
                    .collect(),
            ),
            RekeyEditAction::AddAnarchy(dim, attrs) => CoverCryptRekeyAction::AddAnarchy(
                dim.clone(),
                attrs.iter().map(|(a, h)| (attr(a), hint(*h))).collect(),
            ),
            RekeyEditAction::AddHierarchy(dim, attrs) => CoverCryptRekeyAction::AddHierarchy(
                dim.clone(),
                attrs.iter().map(|(a, h)| (attr(a), hint(*h))).collect(),
            ),
        }
    }

    fn every_action() -> Vec<RekeyEditAction> {
        let qa = |d: &str, n: &str| QualifiedAttribute::new(d, n);
        vec![
            RekeyEditAction::RekeyAccessPolicy("Department::HR && Security::Secret".to_owned()),
            RekeyEditAction::PruneAccessPolicy("Department::HR".to_owned()),
            RekeyEditAction::DeleteAttribute(vec![qa("Department", "HR"), qa("Security", "Low")]),
            RekeyEditAction::DisableAttribute(vec![qa("Department", "HR")]),
            RekeyEditAction::AddAttribute(vec![
                (
                    qa("Security", "Medium"),
                    EncryptionHint::Classic,
                    Some("Low".to_owned()),
                ),
                (qa("Department", "IT"), EncryptionHint::Hybridized, None),
                (qa("Department", "Legal"), EncryptionHint::PostQuantum, None),
            ]),
            RekeyEditAction::RenameAttribute(vec![(qa("Department", "HR"), "People".to_owned())]),
            RekeyEditAction::AddAnarchy(
                "Country".to_owned(),
                vec![
                    (qa("Country", "France"), EncryptionHint::Classic),
                    (qa("Country", "Germany"), EncryptionHint::Hybridized),
                ],
            ),
            RekeyEditAction::AddHierarchy(
                "Level".to_owned(),
                vec![
                    (qa("Level", "Low"), EncryptionHint::Classic),
                    (qa("Level", "High"), EncryptionHint::Classic),
                ],
            ),
        ]
    }

    /// Every action built client-side (`build_covercrypt_rekey_keypair_request`, what the
    /// WASM client exposes) is the very request the server-side builder makes, and the server
    /// reads it back as the same action.
    #[test]
    fn client_rekey_actions_match_the_server_ones() {
        for action in every_action() {
            let server = build_rekey_keypair_request(VENDOR, "msk", &action).unwrap();
            let client =
                build_covercrypt_rekey_keypair_request(VENDOR, "msk", &mirror(&action)).unwrap();
            assert_eq!(
                serde_json::to_string(&client).unwrap(),
                serde_json::to_string(&server).unwrap(),
                "{action:?}"
            );
            let read_back = rekey_edit_action_from_attributes(
                VENDOR,
                client.private_key_attributes.as_ref().expect("attributes"),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_string(&read_back).unwrap(),
                serde_json::to_string(&action).unwrap(),
                "{action:?}"
            );
        }
    }
}
