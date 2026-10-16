//! `CoverCrypt` access structure edits (`ReKeyKeyPair` requests), usable from WASM.

pub use cosmian_cover_crypt::{AccessPolicy, EncryptionHint, QualifiedAttribute};
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_operations::ReKeyKeyPair,
    kmip_types::{
        CryptographicAlgorithm, KeyFormatType, UniqueIdentifier, VendorAttribute,
        VendorAttributeValue,
    },
};
use serde::Serialize;

use crate::{cover_crypt_utils::VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION, error::UtilsError};

/// Parse an encryption hint: `Classic`, `PostQuantum` or `Hybridized` (case-insensitive,
/// `-` and `_` ignored).
pub fn parse_encryption_hint(s: &str) -> Result<EncryptionHint, UtilsError> {
    match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "classic" => Ok(EncryptionHint::Classic),
        "postquantum" => Ok(EncryptionHint::PostQuantum),
        "hybridized" => Ok(EncryptionHint::Hybridized),
        _ => Err(UtilsError::Default(format!(
            "invalid CoverCrypt encryption hint: '{s}' (expected Classic, PostQuantum or Hybridized)"
        ))),
    }
}

/// Parse a qualified attribute written `"Dimension::name"`.
pub fn parse_qualified_attribute(s: &str) -> Result<QualifiedAttribute, UtilsError> {
    QualifiedAttribute::try_from(s).map_err(|e| UtilsError::Default(e.to_string()))
}

/// Check that `s` is a valid access policy, e.g. `"Department::HR && Security::Secret"`.
pub fn check_access_policy(s: &str) -> Result<(), UtilsError> {
    AccessPolicy::parse(s)
        .map(|_| ())
        .map_err(|e| UtilsError::Default(format!("invalid access policy '{s}': {e}")))
}

/// Client-side copy of the server's `RekeyEditAction`, which cannot be built for WASM.
/// Both must serialize identically: `cosmian_kms_crypto` tests the round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CoverCryptRekeyAction {
    /// Renew the secrets of every right the access policy covers.
    RekeyAccessPolicy(String),
    /// Remove all but the latest secret of every right the access policy covers.
    PruneAccessPolicy(String),
    /// Remove attributes from the access structure.
    DeleteAttribute(Vec<QualifiedAttribute>),
    /// Stop encrypting for attributes (decryption keeps working).
    DisableAttribute(Vec<QualifiedAttribute>),
    /// Add attributes, each with its encryption hint and — in a hierarchical dimension —
    /// the existing attribute name it ranks right above (`None`: at the very bottom).
    AddAttribute(Vec<(QualifiedAttribute, EncryptionHint, Option<String>)>),
    /// Rename attributes: each qualified attribute with its new (unqualified) name.
    RenameAttribute(Vec<(QualifiedAttribute, String)>),
    /// Add a non-hierarchical dimension with its attributes.
    AddAnarchy(String, Vec<(QualifiedAttribute, EncryptionHint)>),
    /// Add a hierarchical dimension with its attributes, lowest first.
    AddHierarchy(String, Vec<(QualifiedAttribute, EncryptionHint)>),
}

/// Build the `ReKeyKeyPair` request performing `action` on the access structure of the
/// master secret key `msk_uid`.
pub fn build_covercrypt_rekey_keypair_request(
    vendor_id: String,
    msk_uid: UniqueIdentifier,
    action: &CoverCryptRekeyAction,
) -> Result<ReKeyKeyPair, UtilsError> {
    let action = serde_json::to_vec(action).map_err(|e| {
        UtilsError::Default(format!("failed serializing the CoverCrypt action: {e}"))
    })?;
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(msk_uid),
        private_key_attributes: Some(Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            vendor_attributes: Some(vec![VendorAttribute {
                vendor_identification: vendor_id,
                attribute_name: VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION.to_owned(),
                attribute_value: VendorAttributeValue::ByteString(action),
            }]),
            ..Attributes::default()
        }),
        ..ReKeyKeyPair::default()
    })
}

#[cfg(test)]
mod tests {
    use super::{QualifiedAttribute, check_access_policy, parse_qualified_attribute};

    #[test]
    fn qualified_attributes_parse() {
        assert_eq!(
            parse_qualified_attribute("D::a").map_err(|e| e.to_string()),
            Ok(QualifiedAttribute::new("D", "a"))
        );
        assert_eq!(parse_qualified_attribute("D:a").ok(), None);
        assert_eq!(parse_qualified_attribute("D::a::b").ok(), None);
    }

    #[test]
    fn access_policies_check() {
        assert_eq!(
            check_access_policy("D::a && (E::x || E::y)").map_err(|e| e.to_string()),
            Ok(())
        );
        assert_eq!(check_access_policy("D::a E::x").ok(), None);
    }
}
