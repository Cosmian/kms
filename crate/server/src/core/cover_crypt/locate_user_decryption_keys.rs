use std::sync::Arc;

use cosmian_cover_crypt::QualifiedAttribute;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::Locate,
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
        StateEnumeration,
    },
};
use cosmian_kms_crypto::crypto::cover_crypt::attributes::qualified_attributes_as_vendor_attributes;
use cosmian_kms_interfaces::SessionParams;

use crate::{
    core::{KMS, operations},
    result::KResult,
};

/// Locate all the user decryption keys associated with the master secret key
/// and for the given access structure attributes
pub(crate) async fn locate_usk(
    kmip_server: &KMS,
    master_secret_key_uid: &str,
    cover_crypt_policy_attributes_to_revoke: Option<Vec<QualifiedAttribute>>,
    state: Option<StateEnumeration>,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<Option<Vec<String>>> {
    // Convert the access structure attributes to vendor attributes
    let vendor_attributes = match cover_crypt_policy_attributes_to_revoke {
        Some(att) => Some(vec![qualified_attributes_as_vendor_attributes(&att)?]),
        None => None,
    };
    // Search the user decryption keys that need to be refreshed
    let search_attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes,
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_secret_key_uid.to_owned(),
            ),
        }]),
        ..Attributes::default()
    };
    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response =
        operations::locate(kmip_server, locate_request, state, owner, params).await?;
    Ok(locate_response.unique_identifiers.map(|ids| {
        ids.into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<String>>()
    }))
}
