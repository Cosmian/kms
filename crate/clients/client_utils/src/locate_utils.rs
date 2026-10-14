use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_operations::Locate,
    kmip_types::{CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier},
};

use crate::error::UtilsError;

/// Attribute criteria used to filter objects in a `Locate` request.
#[derive(Debug, Clone, Default)]
pub struct LocateCriteria {
    /// Cryptographic algorithm of the object
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    /// Cryptographic length of the object, in bits
    pub cryptographic_length: Option<i32>,
    /// Key format type of the object
    pub key_format_type: Option<KeyFormatType>,
    /// KMIP object type
    pub object_type: Option<ObjectType>,
}

/// Identifiers of linked objects (certificate, private key, public key) used
/// to locate or to import objects with links.
#[derive(Debug, Clone, Default)]
pub struct ObjectLinkIds {
    /// Identifier of the linked certificate
    pub certificate_id: Option<String>,
    /// Identifier of the linked private key
    pub private_key_id: Option<String>,
    /// Identifier of the linked public key
    pub public_key_id: Option<String>,
}

/// Build a KMIP `Locate` request from tags, attribute criteria and linked object ids.
///
/// # Errors
/// Returns an error if the tags cannot be set on the attributes.
pub fn build_locate_request(
    vendor_id: &str,
    tags: Option<Vec<String>>,
    criteria: &LocateCriteria,
    link_ids: &ObjectLinkIds,
) -> Result<Locate, UtilsError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: criteria.cryptographic_algorithm,
        cryptographic_length: criteria.cryptographic_length,
        key_format_type: criteria.key_format_type,
        object_type: criteria.object_type,
        ..Attributes::default()
    };

    if let Some(public_key_id) = &link_ids.public_key_id {
        attributes.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(public_key_id.clone()),
        );
    }

    if let Some(private_key_id) = &link_ids.private_key_id {
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(private_key_id.clone()),
        );
    }

    if let Some(certificate_id) = &link_ids.certificate_id {
        attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(certificate_id.clone()),
        );
    }

    if let Some(tags) = tags {
        attributes.set_tags(vendor_id, tags)?;
    }
    Ok(Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes,
    })
}
