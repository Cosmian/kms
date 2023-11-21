use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{GetAttributes, GetAttributesResponse},
    kmip_types::{
        AttributeReference, Attributes, KeyFormatType, LinkType, LinkedObjectIdentifier, Tag,
    },
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::{debug, trace};

use crate::{
    core::{certificate::add_certificate_tags_to_attributes, KMS},
    database::retrieve_object_for_operation,
    error::KmsError,
    result::KResult,
};

pub async fn get_attributes(
    kms: &KMS,
    request: GetAttributes,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetAttributesResponse> {
    trace!("Get attributes: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    let owm = retrieve_object_for_operation(
        &uid_or_tags,
        ObjectOperationType::GetAttributes,
        kms,
        user,
        params,
    )
    .await?;
    let object_type = owm.object.object_type();

    let attributes = match &owm.object {
        Object::Certificate { .. } => {
            let mut attributes = Attributes::default();
            add_certificate_tags_to_attributes(&mut attributes, &owm.id, kms, params).await?;
            attributes.key_format_type = Some(KeyFormatType::X509);
            attributes.object_type = Some(ObjectType::Certificate);
            attributes
        }
        Object::CertificateRequest { .. }
        | Object::OpaqueObject { .. }
        | Object::PGPKey { .. }
        | Object::SecretData { .. }
        | Object::SplitKey { .. } => {
            return Err(KmsError::InvalidRequest(format!(
                "get: unsupported object type for {uid_or_tags}",
            )))
        }
        Object::PrivateKey { key_block }
        | Object::PublicKey { key_block }
        | Object::SymmetricKey { key_block } => {
            let mut attributes = key_block.key_value.attributes.clone().unwrap_or_default();
            attributes.object_type = Some(ObjectType::SplitKey);
            attributes
        }
    };

    // recover an active object
    // let owm = get_active_object(kms, &uid_or_tags, user, params).await?;

    let req_attributes = match &request.attribute_references {
        None => {
            return Ok(GetAttributesResponse {
                unique_identifier: owm.id,
                attributes: attributes.clone(),
            })
        }
        Some(attrs) => attrs,
    };
    let mut res = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(req_vdr_attr) => {
                if let Some(vdr_attrs) = attributes.vendor_attributes.as_ref() {
                    let mut list = res
                        .vendor_attributes
                        .as_ref()
                        .map_or(Vec::new(), std::clone::Clone::clone);
                    vdr_attrs
                        .iter()
                        .filter(|attr| {
                            attr.vendor_identification == req_vdr_attr.vendor_identification
                                && attr.attribute_name == req_vdr_attr.attribute_name
                        })
                        .for_each(|vdr_attr| {
                            list.push(vdr_attr.clone());
                        });
                    if !list.is_empty() {
                        res.vendor_attributes = Some(list);
                    }
                }
            }
            AttributeReference::Standard(tag) => match tag {
                Tag::ActivationDate => {
                    res.activation_date = attributes.activation_date;
                }
                Tag::CryptographicAlgorithm => {
                    res.cryptographic_algorithm = attributes.cryptographic_algorithm;
                }
                Tag::CryptographicLength => {
                    res.cryptographic_length = attributes.cryptographic_length;
                }
                Tag::CryptographicParameters => {
                    res.cryptographic_parameters = attributes.cryptographic_parameters.clone();
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask.clone();
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                Tag::PrivateKey => {
                    attributes.get_link(LinkType::PrivateKeyLink).map(|link| {
                        res.add_link(
                            LinkType::PrivateKeyLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    });
                }
                Tag::PublicKey => {
                    attributes.get_link(LinkType::PublicKeyLink).map(|link| {
                        res.add_link(
                            LinkType::PublicKeyLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    });
                }
                Tag::Certificate => {
                    attributes
                        .get_link(LinkType::PKCS12CertificateLink)
                        .map(|link| {
                            res.add_link(
                                LinkType::PKCS12CertificateLink,
                                LinkedObjectIdentifier::TextString(link.clone()),
                            );
                        });
                    attributes.get_link(LinkType::CertificateLink).map(|link| {
                        res.add_link(
                            LinkType::CertificateLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    });
                }
                _ => {}
            },
        }
    }
    debug!("Retrieved Attributes for object {}: {:?}", owm.id, res);
    Ok(GetAttributesResponse {
        unique_identifier: owm.id,
        attributes: res,
    })
}
