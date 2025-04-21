use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_operations::Locate,
    kmip_types::{CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier},
};

use crate::error::UtilsError;

#[allow(clippy::too_many_arguments)]
pub fn build_locate_request(
    tags: Option<Vec<String>>,
    cryptographic_algorithm: Option<CryptographicAlgorithm>,
    cryptographic_length: Option<i32>,
    key_format_type: Option<KeyFormatType>,
    object_type: Option<ObjectType>,
    public_key_id: Option<&str>,
    private_key_id: Option<&str>,
    certificate_id: Option<&str>,
) -> Result<Locate, UtilsError> {
    let mut attributes = Attributes::default();

    if let Some(crypto_algo) = cryptographic_algorithm {
        attributes.cryptographic_algorithm = Some(crypto_algo);
    }

    if let Some(cryptographic_length) = cryptographic_length {
        attributes.cryptographic_length = Some(cryptographic_length);
    }

    if let Some(key_format_type) = key_format_type {
        attributes.key_format_type = Some(key_format_type);
    }

    if let Some(object_type) = object_type {
        attributes.object_type = Some(object_type);
    }

    if let Some(public_key_id) = &public_key_id {
        attributes.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString((*public_key_id).to_owned()),
        );
    }

    if let Some(private_key_id) = &private_key_id {
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString((*private_key_id).to_owned()),
        );
    }

    if let Some(certificate_id) = &certificate_id {
        attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString((*certificate_id).to_owned()),
        );
    }

    if let Some(tags) = tags {
        attributes.set_tags(tags)?;
    }
    Ok(Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes,
    })
}
