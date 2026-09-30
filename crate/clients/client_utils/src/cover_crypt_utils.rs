use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, CreateKeyPair, ReKeyKeyPair},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier, VendorAttribute, VendorAttributeValue,
        },
    },
    time_normalize,
};

use std::str::FromStr;

use serde::Serialize;

use crate::error::UtilsError;
pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE: &str = "cover_crypt_access_structure";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION: &str = "cover_crypt_rekey_action";

/// Build a `CreateKeyPair` request for an `CoverCrypt` Master Key
pub fn build_create_covercrypt_master_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    vendor_id: &str,
    access_structure: &str,
    tags: T,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<CreateKeyPair, UtilsError> {
    let vendor_attributes = VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(access_structure.as_bytes().to_vec()),
    };

    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![vendor_attributes]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        sensitive: sensitive.then_some(true),

        activation_date: Some(time_normalize().map_err(|e| UtilsError::Default(e.to_string()))?),
        ..Attributes::default()
    };
    attributes.set_tags(vendor_id, tags)?;

    if let Some(wrap_key_id) = wrapping_key_id {
        attributes.set_wrapping_key_id(vendor_id, wrap_key_id);
    }

    let request = CreateKeyPair {
        common_attributes: Some(attributes),
        ..CreateKeyPair::default()
    };

    Ok(request)
}

/// Build a `Create` request for a `CoverCrypt` USK
pub fn build_create_covercrypt_usk_request<T: IntoIterator<Item = impl AsRef<str>>>(
    vendor_id: &str,
    access_policy: &str,
    cover_crypt_master_secret_key_id: &str,
    tags: T,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<Create, UtilsError> {
    let vendor_attributes: VendorAttribute = VendorAttribute {
        vendor_identification: vendor_id.to_owned(),
        attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY.to_owned(),
        attribute_value: VendorAttributeValue::ByteString(access_policy.as_bytes().to_vec()),
    };
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![vendor_attributes]),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                cover_crypt_master_secret_key_id.to_owned(),
            ),
        }]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        sensitive: sensitive.then_some(true),
        activation_date: Some(time_normalize().map_err(|e| UtilsError::Default(e.to_string()))?),
        ..Attributes::default()
    };
    attributes.set_tags(vendor_id, tags)?;
    if let Some(wrap_key_id) = wrapping_key_id {
        attributes.set_wrapping_key_id(vendor_id, wrap_key_id);
    }

    let request = Create {
        attributes,
        object_type: ObjectType::PrivateKey,
        protection_storage_masks: None,
    };

    Ok(request)
}

/// The encryption hint of a new `CoverCrypt` attribute — mirrors `cosmian_cover_crypt`'s
/// `EncryptionHint`, which serializes to the same variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CoverCryptEncryptionHint {
    /// Pre-quantum encryption only.
    Classic,
    /// Post-quantum encryption only.
    PostQuantum,
    /// Pre- and post-quantum (hybridized) encryption.
    Hybridized,
}

impl FromStr for CoverCryptEncryptionHint {
    type Err = UtilsError;

    /// `Classic`, `PostQuantum` or `Hybridized` — case-insensitive, `-`/`_` ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "classic" => Ok(Self::Classic),
            "postquantum" => Ok(Self::PostQuantum),
            "hybridized" => Ok(Self::Hybridized),
            _ => Err(UtilsError::Default(format!(
                "invalid CoverCrypt encryption hint: '{s}' (expected Classic, PostQuantum or Hybridized)"
            ))),
        }
    }
}

/// A `CoverCrypt` master key edit, as carried by a `ReKeyKeyPair` request — the client-side
/// mirror of `cosmian_kms_crypto`'s `RekeyEditAction`, with plain strings in place of its
/// `cosmian_cover_crypt` types: a qualified attribute is written `"Dimension::name"`. It
/// serializes to the exact same JSON (the vendor attribute the server reads back as a
/// `RekeyEditAction`), without pulling `cosmian_cover_crypt` — and with it OpenSSL — into
/// builds that can't have it, such as the WASM client. Its variants must stay in the same
/// shape as `RekeyEditAction`'s: `cosmian_kms_crypto`'s tests check both serialize alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CoverCryptRekeyAction {
    /// Renew the secrets of every right the access policy covers.
    RekeyAccessPolicy(String),
    /// Remove all but the latest secret of every right the access policy covers.
    PruneAccessPolicy(String),
    /// Remove attributes from the access structure.
    DeleteAttribute(Vec<String>),
    /// Stop encrypting for attributes (decryption keeps working).
    DisableAttribute(Vec<String>),
    /// Add attributes, each with its encryption hint and — in a hierarchical dimension —
    /// the existing attribute name it ranks right above (`None`: at the very bottom).
    AddAttribute(Vec<(String, CoverCryptEncryptionHint, Option<String>)>),
    /// Rename attributes: each qualified attribute with its new (unqualified) name.
    RenameAttribute(Vec<(String, String)>),
    /// Add a non-hierarchical dimension with its attributes.
    AddAnarchy(String, Vec<(String, CoverCryptEncryptionHint)>),
    /// Add a hierarchical dimension with its attributes, lowest first.
    AddHierarchy(String, Vec<(String, CoverCryptEncryptionHint)>),
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
#[allow(clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;

    use super::{CoverCryptEncryptionHint as Hint, CoverCryptRekeyAction as Action};

    #[test]
    fn encryption_hints_parse() {
        assert_eq!(Hint::from_str("Classic").unwrap(), Hint::Classic);
        assert_eq!(Hint::from_str("post-quantum").unwrap(), Hint::PostQuantum);
        assert_eq!(Hint::from_str("HYBRIDIZED").unwrap(), Hint::Hybridized);
        Hint::from_str("quantum").unwrap_err();
    }

    /// The JSON the server reads back as a `RekeyEditAction` — `cosmian_kms_crypto`'s
    /// tests check it's also what `RekeyEditAction` itself produces.
    #[test]
    fn rekey_actions_serialize_like_the_server_expects() {
        let json = |action: &Action| serde_json::to_string(action).unwrap();
        assert_eq!(
            json(&Action::RekeyAccessPolicy("D::a".to_owned())),
            r#"{"RekeyAccessPolicy":"D::a"}"#
        );
        assert_eq!(
            json(&Action::AddAttribute(vec![(
                "D::b".to_owned(),
                Hint::Classic,
                Some("a".to_owned())
            )])),
            r#"{"AddAttribute":[["D::b","Classic","a"]]}"#
        );
        assert_eq!(
            json(&Action::AddAttribute(vec![(
                "D::b".to_owned(),
                Hint::Hybridized,
                None
            )])),
            r#"{"AddAttribute":[["D::b","Hybridized",null]]}"#
        );
        assert_eq!(
            json(&Action::RenameAttribute(vec![(
                "D::a".to_owned(),
                "z".to_owned()
            )])),
            r#"{"RenameAttribute":[["D::a","z"]]}"#
        );
        assert_eq!(
            json(&Action::AddHierarchy(
                "E".to_owned(),
                vec![("E::x".to_owned(), Hint::Classic)]
            )),
            r#"{"AddHierarchy":["E",[["E::x","Classic"]]]}"#
        );
    }
}
