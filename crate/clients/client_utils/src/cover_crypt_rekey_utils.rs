//! `CoverCrypt` master key edits (`ReKeyKeyPair` requests), usable from WASM.
//!
//! Only built with `non-fips`: it depends on `cosmian_cover_crypt`, whose algorithms are not
//! FIPS-approved — the same gating as `cosmian_kms_crypto`'s `cover_crypt` module.

pub use cosmian_cover_crypt::{EncryptionHint, QualifiedAttribute};
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

/// Parse the encryption hint of a new `CoverCrypt` attribute: `Classic`, `PostQuantum` or
/// `Hybridized` — case-insensitive, `-`/`_` ignored (`EncryptionHint` has no `FromStr`).
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

/// A `CoverCrypt` master key edit, as carried by a `ReKeyKeyPair` request — the client-side
/// mirror of `cosmian_kms_crypto`'s `RekeyEditAction`, built on the same `cosmian_cover_crypt`
/// types. `RekeyEditAction` lives in `cosmian_kms_crypto`, which depends on OpenSSL and
/// can't be built for WASM; this mirror only needs `cosmian_cover_crypt` without OpenSSL.
/// It serializes to the exact same JSON (the vendor attribute the server reads back as a
/// `RekeyEditAction`): its variants must stay in the same shape as `RekeyEditAction`'s, which
/// `cosmian_kms_crypto`'s tests check.
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

/// Build a `ReKeyKeyPair` request applying `action` to the `CoverCrypt` master key pair
/// whose master secret key is `msk_uid` — the same request as `cosmian_kms_crypto`'s
/// `build_rekey_keypair_request`.
pub fn build_covercrypt_rekey_keypair_request(
    vendor_id: &str,
    msk_uid: &str,
    action: &CoverCryptRekeyAction,
) -> Result<ReKeyKeyPair, UtilsError> {
    let action = serde_json::to_vec(action).map_err(|e| {
        UtilsError::Default(format!("failed serializing the CoverCrypt action: {e}"))
    })?;
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(msk_uid.to_owned())),
        private_key_attributes: Some(Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            vendor_attributes: Some(vec![VendorAttribute {
                vendor_identification: vendor_id.to_owned(),
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
    use super::{
        CoverCryptRekeyAction as Action, EncryptionHint as Hint, QualifiedAttribute,
        parse_encryption_hint, parse_qualified_attribute,
    };

    #[test]
    fn encryption_hints_parse() {
        let parse = |s: &str| parse_encryption_hint(s).map_err(|e| e.to_string());
        assert_eq!(parse("Classic"), Ok(Hint::Classic));
        assert_eq!(parse("post-quantum"), Ok(Hint::PostQuantum));
        assert_eq!(parse("HYBRIDIZED"), Ok(Hint::Hybridized));
        assert_eq!(parse("quantum").ok(), None);
    }

    #[test]
    fn qualified_attributes_parse() {
        assert_eq!(
            parse_qualified_attribute("D::a").map_err(|e| e.to_string()),
            Ok(QualifiedAttribute::new("D", "a"))
        );
        assert_eq!(parse_qualified_attribute("D:a").ok(), None);
        assert_eq!(parse_qualified_attribute("D::a::b").ok(), None);
    }

    /// The JSON the server reads back as a `RekeyEditAction` — `cosmian_kms_crypto`'s
    /// tests check it's also what `RekeyEditAction` itself produces.
    #[test]
    fn rekey_actions_serialize_like_the_server_expects() {
        let json = |action: &Action| serde_json::to_string(action).map_err(|e| e.to_string());
        assert_eq!(
            json(&Action::RekeyAccessPolicy("D::a".to_owned())),
            Ok(r#"{"RekeyAccessPolicy":"D::a"}"#.to_owned())
        );
        assert_eq!(
            json(&Action::AddAttribute(vec![(
                QualifiedAttribute::new("D", "b"),
                Hint::Classic,
                Some("a".to_owned())
            )])),
            Ok(r#"{"AddAttribute":[["D::b","Classic","a"]]}"#.to_owned())
        );
        assert_eq!(
            json(&Action::AddAttribute(vec![(
                QualifiedAttribute::new("D", "b"),
                Hint::Hybridized,
                None
            )])),
            Ok(r#"{"AddAttribute":[["D::b","Hybridized",null]]}"#.to_owned())
        );
        assert_eq!(
            json(&Action::RenameAttribute(vec![(
                QualifiedAttribute::new("D", "a"),
                "z".to_owned()
            )])),
            Ok(r#"{"RenameAttribute":[["D::a","z"]]}"#.to_owned())
        );
        assert_eq!(
            json(&Action::AddHierarchy(
                "E".to_owned(),
                vec![(QualifiedAttribute::new("E", "x"), Hint::Classic)]
            )),
            Ok(r#"{"AddHierarchy":["E",[["E::x","Classic"]]]}"#.to_owned())
        );
    }
}
