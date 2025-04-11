use cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, KeyWrapType},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_operations::{Create, CreateKeyPair, Destroy, Import, Locate, ReKeyKeyPair},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier, WrappingMethod,
        },
    },
};

use super::attributes::{RekeyEditAction, rekey_edit_action_as_vendor_attribute};
use crate::error::CryptoError;

/// Build a `ReKeyKeyPair` request.
/// To re-key an attribute of a user decryption key, we first need:
/// - the MSK UID
/// - the `CoverCrypt` attributes to revoke
/// - the `ReKeyKeyPairAction` to perform
///
/// The routine will then locate and renew all user decryption keys linked to
/// this MSK.
pub fn build_rekey_keypair_request(
    msk_uid: &str,
    action: &RekeyEditAction,
) -> Result<ReKeyKeyPair, CryptoError> {
    Ok(ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(msk_uid.to_owned())),
        private_key_attributes: Some(Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            vendor_attributes: Some(vec![rekey_edit_action_as_vendor_attribute(action)?]),
            ..Attributes::default()
        }),
        ..ReKeyKeyPair::default()
    })
}
