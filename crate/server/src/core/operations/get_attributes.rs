use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        extra::{VENDOR_ID_COSMIAN, tagging::VENDOR_ATTR_TAG},
        kmip_attributes::Attributes,
        kmip_data_structures::KeyValue,
        kmip_objects::{Object, PrivateKey, PublicKey, SecretData, SymmetricKey},
        kmip_operations::{GetAttributes, GetAttributesResponse},
        kmip_types::{
            AttributeReference, LinkType, Tag, UniqueIdentifier, VendorAttribute,
            VendorAttributeReference,
        },
    },
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::{debug, trace};
use strum::IntoEnumIterator;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
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

    let attributes = match owm.object() {
        Object::Certificate { .. } => {
            // KMIP Attributes retrieved from the dedicated column `Attributes`
            owm.attributes().to_owned()
        }
        Object::PrivateKey(PrivateKey { key_block })
        | Object::PublicKey(PublicKey { key_block })
        | Object::SymmetricKey(SymmetricKey { key_block })
        | Object::SecretData(SecretData { key_block, .. }) => {
            if let Some(KeyValue::Structure {
                attributes: Some(attributes),
                ..
            }) = key_block.key_value.as_ref()
            {
                let mut attributes = attributes.clone();
                attributes.merge(owm.attributes(), false);
                attributes
            } else {
                owm.attributes().to_owned()
            }
        }
        Object::CertificateRequest { .. }
        | Object::OpaqueObject { .. }
        | Object::PGPKey { .. }
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
    let mut tags_already_set = false;
    let mut res = Attributes::default();
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification,
                attribute_name,
            }) => {
                if vendor_identification == VENDOR_ID_COSMIAN && attribute_name == VENDOR_ATTR_TAG {
                    if ! tags_already_set {
                        let tags = kms.database.retrieve_tags(owm.id(), params.clone()).await?;
                        res.set_tags(tags)?;
                        tags_already_set = true;
                    }
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
                Tag::AlwaysSensitive => {
                    res.always_sensitive = attributes.always_sensitive;
                }
                Tag::ApplicationSpecificInformation => {
                    attributes
                        .application_specific_information
                        .clone_into(&mut res.application_specific_information);
                }
                Tag::ArchiveDate => {
                    res.archive_date = attributes.archive_date;
                }
                Tag::Certificate => {
                    if let Some(certificate_attributes) = attributes.certificate_attributes.clone()
                    {
                        res.certificate_attributes = Some(certificate_attributes);
                    }
                }
                Tag::CompromiseDate => {
                    res.compromise_date = attributes.compromise_date;
                }
                Tag::CompromiseOccurrenceDate => {
                    res.compromise_occurrence_date = attributes.compromise_occurrence_date;
                }
                Tag::ContactInformation => {
                    attributes
                        .contact_information
                        .clone_into(&mut res.contact_information);
                }
                Tag::CryptographicAlgorithm => {
                    res.cryptographic_algorithm = attributes.cryptographic_algorithm;
                }
                Tag::CryptographicDomainParameters => {
                    res.cryptographic_domain_parameters =
                        attributes.cryptographic_domain_parameters;
                }
                Tag::CryptographicLength => {
                    res.cryptographic_length = attributes.cryptographic_length;
                }
                Tag::CryptographicParameters => {
                    res.cryptographic_parameters
                        .clone_from(&attributes.cryptographic_parameters);
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask;
                }
                Tag::DeactivationDate => {
                    res.deactivation_date = attributes.deactivation_date;
                }
                Tag::DestroyDate => {
                    res.destroy_date = attributes.destroy_date;
                }
                Tag::Digest => {
                    if let Some(digest) = attributes.digest.clone() {
                        res.digest = Some(digest);
                    }
                }
                Tag::Extractable => {
                    res.extractable = attributes.extractable;
                }
                Tag::InitialDate => {
                    res.initial_date = attributes.initial_date;
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                Tag::LastChangeDate => {
                    res.last_change_date = attributes.last_change_date;
                }
                Tag::Link => {
                    attributes.link.clone_into(&mut res.link);
                }
                Tag::LinkType => {
                    trace!("Get Attributes: LinkType: {:?}", attributes.link);
                    for link_type in LinkType::iter() {
                        if let Some(link) = attributes.get_link(link_type).as_ref() {
                            res.set_link(link_type, link.clone());
                        }
                    }
                }
                Tag::Name => {
                    attributes.name.clone_into(&mut res.name);
                }
                Tag::NeverExtractable => {
                    res.never_extractable = attributes.never_extractable;
                }
                Tag::ObjectGroup => {
                    attributes.object_group.clone_into(&mut res.object_group);
                }
                Tag::ObjectType => {
                    res.object_type = attributes.object_type;
                }
                Tag::OriginalCreationDate => {
                    res.original_creation_date = attributes.original_creation_date;
                }
                Tag::ProcessStartDate => {
                    res.process_start_date = attributes.process_start_date;
                }
                Tag::ProtectStopDate => {
                    res.protect_stop_date = attributes.protect_stop_date;
                }
                Tag::QuantumSafe => {
                    res.quantum_safe = attributes.quantum_safe;
                }
                Tag::RevocationReason => {
                    attributes
                        .revocation_reason
                        .clone_into(&mut res.revocation_reason);
                }
                Tag::Sensitive => {
                    res.sensitive = attributes.sensitive;
                }
                Tag::State => {
                    res.state = attributes.state;
                }
                Tag::UniqueIdentifier => {
                    attributes
                        .unique_identifier
                        .clone_into(&mut res.unique_identifier);
                }
                Tag::VendorExtension => {
                    if let Some(vendor_attributes) = attributes.vendor_attributes.clone() {
                        res.vendor_attributes = Some(vendor_attributes);
                    }
                }
                Tag::Tag => {
                    if ! tags_already_set {
                        let tags = kms.database.retrieve_tags(owm.id(), params.clone()).await?;
                        res.set_tags(tags)?;
                        tags_already_set = true;
                    }
                }
                x => {
                    // we ignore Tags which do not match to attributes
                    trace!("Ignoring tag {x:?} which does not match to an attribute");
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
