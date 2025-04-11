use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    extra::{tagging::VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
    kmip_attributes::Attributes,
    kmip_objects::{Object, PrivateKey, PublicKey, SymmetricKey},
    kmip_operations::{GetAttributes, GetAttributesResponse},
    kmip_types::{
        AttributeReference, KeyFormatType, LinkType, Tag, UniqueIdentifier, VendorAttribute,
        VendorAttributeReference,
    },
};
use cosmian_kms_crypto::openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl};
use cosmian_kms_interfaces::SessionParams;
use strum::IntoEnumIterator;
use tracing::{debug, trace};

use crate::{
    core::{
        KMS,
        operations::export_get::{
            openssl_private_key_to_kmip_default_format, openssl_public_key_to_kmip_default_format,
        },
        retrieve_object_utils::retrieve_object_for_operation,
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn get_attributes(
    kms: &KMS,
    request: GetAttributes,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
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
        KmipOperation::GetAttributes,
        kms,
        user,
        params.clone(),
    )
    .await?;
    trace!(
        "Get Attributes: Retrieved object for get attributes: {}",
        owm.object()
    );
    let object_type = owm.object().object_type();

    let attributes = match owm.object() {
        Object::Certificate { .. } => {
            // KMIP Attributes retrieved from dedicated column `Attributes`
            owm.attributes().to_owned()
        }
        Object::PrivateKey(PrivateKey { key_block }) => {
            let mut attributes = key_block
                .key_value
                .as_ref()
                .and_then(|kv| kv.attributes.clone())
                .unwrap_or_default();
            attributes.object_type = Some(object_type);
            // is it a Covercrypt key?
            if key_block.key_format_type == KeyFormatType::CoverCryptSecretKey {
                attributes
            } else {
                // we want the default format which yields the most infos
                let pkey = kmip_private_key_to_openssl(owm.object())?;
                let default_kmip = openssl_private_key_to_kmip_default_format(
                    &pkey,
                    attributes.cryptographic_usage_mask,
                )?;
                let mut default_attributes = default_kmip.attributes().cloned().unwrap_or_default();
                default_attributes.object_type = Some(object_type);
                //re-add the vendor attributes
                default_attributes
                    .vendor_attributes
                    .clone_from(&attributes.vendor_attributes);
                // re-add the links
                default_attributes.link.clone_from(&owm.attributes().link);
                default_attributes
            }
        }
        Object::PublicKey(PublicKey { key_block }) => {
            let mut attributes = key_block
                .key_value
                .as_ref()
                .and_then(|kv| kv.attributes.clone())
                .unwrap_or_default();
            attributes.object_type = Some(object_type);
            // is it a Covercrypt key?
            if key_block.key_format_type == KeyFormatType::CoverCryptPublicKey {
                attributes
            } else {
                // we want the default format which yields the most infos
                let pkey = kmip_public_key_to_openssl(owm.object())?;
                let default_kmip = openssl_public_key_to_kmip_default_format(
                    &pkey,
                    attributes.cryptographic_usage_mask,
                )?;
                let mut default_attributes = default_kmip.attributes().cloned().unwrap_or_default();
                default_attributes.object_type = Some(object_type);
                //re-add the vendor attributes
                default_attributes
                    .vendor_attributes
                    .clone_from(&attributes.vendor_attributes);
                // re-add the links
                default_attributes.link.clone_from(&owm.attributes().link);
                default_attributes
            }
        }
        Object::SymmetricKey(SymmetricKey { key_block }) => {
            let mut attributes = key_block
                .key_value
                .as_ref()
                .and_then(|kv| kv.attributes.clone())
                .unwrap_or_default();
            attributes.object_type = Some(object_type);
            attributes.link.clone_from(&owm.attributes().link);
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
    };

    trace!("Get Attributes: Attributes: {:?}", attributes);

    let mut req_attributes = request.attribute_reference.unwrap_or_default();
    trace!("Get Attributes: Requested attributes: {req_attributes:?}");

    // request all attributes
    if req_attributes.is_empty() {
        // tags
        req_attributes.push(AttributeReference::Vendor(VendorAttributeReference {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_TAG.to_owned(),
        }));
        // standard attributes
        let mut all_tags = Vec::new();
        for tag in Tag::iter() {
            all_tags.push(tag);
        }

        req_attributes.extend(all_tags.iter().map(|t| AttributeReference::Standard(*t)));
    }

    // request selected attributes
    let mut res = Attributes::default();
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification,
                attribute_name,
            }) => {
                if vendor_identification == VENDOR_ID_COSMIAN && attribute_name == VENDOR_ATTR_TAG {
                    let tags = kms.database.retrieve_tags(owm.id(), params.clone()).await?;
                    res.set_tags(tags)?;
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
                    res.cryptographic_parameters
                        .clone_from(&attributes.cryptographic_parameters);
                }
                Tag::CryptographicDomainParameters => {
                    res.cryptographic_domain_parameters =
                        attributes.cryptographic_domain_parameters;
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask;
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                Tag::ObjectType => {
                    res.object_type = attributes.object_type;
                }
                Tag::LinkType => {
                    trace!("Get Attributes: LinkType: {:?}", attributes.link);
                    for link_type in LinkType::iter() {
                        if let Some(link) = attributes.get_link(link_type).as_ref() {
                            res.set_link(link_type, link.clone());
                        }
                    }
                }
                Tag::UniqueIdentifier => {
                    attributes
                        .unique_identifier
                        .clone_into(&mut res.unique_identifier);
                }
                Tag::Name => {
                    attributes.name.clone_into(&mut res.name);
                }
                Tag::ObjectGroup => {
                    attributes.object_group.clone_into(&mut res.object_group);
                }
                Tag::State => {
                    res.state = attributes.state;
                }
                Tag::InitialDate => {
                    res.initial_date = attributes.initial_date;
                }
                Tag::ArchiveDate => {
                    res.archive_date = attributes.archive_date;
                }
                Tag::DeactivationDate => {
                    res.deactivation_date = attributes.deactivation_date;
                }
                Tag::ProcessStartDate => {
                    res.process_start_date = attributes.process_start_date;
                }
                Tag::ProtectStopDate => {
                    res.protect_stop_date = attributes.protect_stop_date;
                }
                Tag::DestroyDate => {
                    res.destroy_date = attributes.destroy_date;
                }
                Tag::CompromiseDate => {
                    res.compromise_date = attributes.compromise_date;
                }
                Tag::CompromiseOccurrenceDate => {
                    res.compromise_occurrence_date = attributes.compromise_occurrence_date;
                }
                Tag::RevocationReason => {
                    attributes
                        .revocation_reason
                        .clone_into(&mut res.revocation_reason);
                }
                Tag::Certificate => {
                    if let Some(certificate_attributes) = attributes.certificate_attributes.clone()
                    {
                        res.certificate_attributes = Some(certificate_attributes);
                    }
                }
                Tag::VendorExtension => {
                    if let Some(vendor_attributes) = attributes.vendor_attributes.clone() {
                        res.vendor_attributes = Some(vendor_attributes);
                    }
                }
                Tag::ApplicationSpecificInformation => {
                    attributes
                        .application_specific_information
                        .clone_into(&mut res.application_specific_information);
                }
                Tag::Link => {
                    attributes.link.clone_into(&mut res.link);
                }
                Tag::ContactInformation => {
                    attributes
                        .contact_information
                        .clone_into(&mut res.contact_information);
                }
                Tag::LastChangeDate => {
                    res.last_change_date = attributes.last_change_date;
                }
                Tag::Sensitive => {
                    res.sensitive = attributes.sensitive;
                }
                Tag::AlwaysSensitive => {
                    res.always_sensitive = attributes.always_sensitive;
                }
                Tag::Extractable => {
                    res.extractable = attributes.extractable;
                }
                Tag::NeverExtractable => {
                    res.never_extractable = attributes.never_extractable;
                }
                Tag::QuantumSafe => {
                    res.quantum_safe = attributes.quantum_safe;
                }
                x => {
                    return Err(KmsError::InvalidRequest(format!(
                        "get: unsupported attribute {x} for {uid_or_tags}",
                    )))
                }
            },
        }
    }
    debug!(
        "Retrieved Attributes for {} {}, tags {:?}",
        owm.object().object_type(),
        owm.id(),
        res.get_tags()
    );
    trace!("Get Attributes: Response: {res:?}");
    Ok(GetAttributesResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        attributes: res,
    })
}
