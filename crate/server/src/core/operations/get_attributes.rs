use cosmian_kmip::{
    kmip::{
        extra::VENDOR_ID_COSMIAN,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{GetAttributes, GetAttributesResponse},
        kmip_types::{
            AttributeReference, Attributes, KeyFormatType, LinkType, LinkedObjectIdentifier, Tag,
            UniqueIdentifier, VendorAttribute, VendorAttributeReference,
        },
    },
    openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    tagging::VENDOR_ATTR_TAG,
};
use tracing::{debug, trace};

use crate::{
    core::{
        certificate::add_certificate_tags_to_attributes,
        operations::export_utils::{
            openssl_private_key_to_kmip_default_format, openssl_public_key_to_kmip_default_format,
        },
        KMS,
    },
    database::retrieve_object_for_operation,
    error::KmsError,
    result::{KResult, KResultHelper},
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
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Get Attributes: the unique identifier must be a string")?;

    let owm = retrieve_object_for_operation(
        uid_or_tags,
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
        Object::PrivateKey { key_block } => {
            // is it a Covercrypt key?
            if key_block.key_format_type == KeyFormatType::CoverCryptSecretKey {
                let mut attributes = key_block.key_value.attributes.clone().unwrap_or_default();
                attributes.object_type = Some(object_type);
                attributes
            } else {
                // we want the default format which yields the most infos
                let pkey = kmip_private_key_to_openssl(&owm.object)?;
                let default_kmip = openssl_private_key_to_kmip_default_format(&pkey)?;
                let mut attributes = default_kmip.attributes().cloned().unwrap_or_default();
                attributes.object_type = Some(object_type);
                attributes
            }
        }
        Object::PublicKey { key_block } => {
            // is it a Covercrypt key?
            if key_block.key_format_type == KeyFormatType::CoverCryptPublicKey {
                let mut attributes = key_block.key_value.attributes.clone().unwrap_or_default();
                attributes.object_type = Some(object_type);
                attributes
            } else {
                // we want the default format which yields the most infos
                let pkey = kmip_public_key_to_openssl(&owm.object)?;
                let default_kmip = openssl_public_key_to_kmip_default_format(&pkey)?;
                let mut attributes = default_kmip.attributes().cloned().unwrap_or_default();
                attributes.object_type = Some(object_type);
                attributes
            }
        }
        Object::SymmetricKey { key_block } => {
            let mut attributes = key_block.key_value.attributes.clone().unwrap_or_default();
            attributes.object_type = Some(object_type);
            attributes
        }
    };

    let req_attributes = request.attribute_references.unwrap_or_default();

    // request all attributes
    if req_attributes.is_empty() {
        let mut attributes = attributes.clone();
        let tags = kms.db.retrieve_tags(&owm.id, params).await?;
        attributes.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            VENDOR_ATTR_TAG,
            serde_json::to_vec(&tags)?,
        );
        return Ok(GetAttributesResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id.clone()),
            attributes,
        })
    };

    // request selected attributes
    let mut res = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification,
                attribute_name,
            }) => {
                if vendor_identification == VENDOR_ID_COSMIAN && attribute_name == VENDOR_ATTR_TAG {
                    let tags = kms.db.retrieve_tags(&owm.id, params).await?;
                    res.add_vendor_attribute(VendorAttribute {
                        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
                        attribute_name: VENDOR_ATTR_TAG.to_owned(),
                        attribute_value: serde_json::to_vec(&tags)?,
                    });
                } else if let Some(value) =
                    attributes.get_vendor_attribute_value(&vendor_identification, &attribute_name)
                {
                    res.add_vendor_attribute(VendorAttribute {
                        vendor_identification,
                        attribute_name,
                        attribute_value: value.to_owned(),
                    });
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
                Tag::CryptographicDomainParameters => {
                    res.cryptographic_domain_parameters =
                        attributes.cryptographic_domain_parameters;
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask.clone();
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                Tag::PrivateKey => {
                    if let Some(link) = attributes.get_link(LinkType::PrivateKeyLink) {
                        res.add_link(
                            LinkType::PrivateKeyLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    }
                }
                Tag::PublicKey => {
                    if let Some(link) = attributes.get_link(LinkType::PublicKeyLink) {
                        res.add_link(
                            LinkType::PublicKeyLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    }
                }
                Tag::Certificate => {
                    if let Some(link) = attributes.get_link(LinkType::PKCS12CertificateLink) {
                        res.add_link(
                            LinkType::PKCS12CertificateLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    }
                    if let Some(link) = attributes.get_link(LinkType::CertificateLink) {
                        res.add_link(
                            LinkType::CertificateLink,
                            LinkedObjectIdentifier::TextString(link.clone()),
                        );
                    }
                }

                _ => {}
            },
        }
    }
    debug!("Retrieved Attributes for object {}: {:?}", owm.id, res);
    Ok(GetAttributesResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id.clone()),
        attributes: res,
    })
}
