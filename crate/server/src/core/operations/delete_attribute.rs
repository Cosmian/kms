use cosmian_kmip::kmip::{
    kmip_operations::{DeleteAttribute, DeleteAttributeResponse},
    kmip_types::{Attribute, AttributeReference, Tag, UniqueIdentifier},
    KmipOperation,
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::trace;

use crate::{
    core::{retrieve_object_utils::retrieve_object_for_operation, KMS},
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn delete_attribute(
    kms: &KMS,
    request: DeleteAttribute,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<DeleteAttributeResponse> {
    trace!("Delete attribute: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Delete Attribute: the unique identifier must be a string")?;

    let mut owm =
        retrieve_object_for_operation(uid_or_tags, KmipOperation::GetAttributes, kms, user, params)
            .await?;
    trace!("Delete Attribute: Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes().to_owned();

    if let Some(attribute) = request.current_attribute {
        match attribute {
            Attribute::ActivationDate(activation_date) => {
                if Some(activation_date) == attributes.activation_date {
                    attributes.activation_date = None;
                }
            }
            Attribute::CryptographicAlgorithm(algo) => {
                if Some(algo) == attributes.cryptographic_algorithm {
                    attributes.cryptographic_algorithm = None;
                }
            }
            Attribute::CryptographicLength(length) => {
                if Some(length) == attributes.cryptographic_length {
                    attributes.cryptographic_length = None;
                }
            }
            Attribute::CryptographicParameters(parameters) => {
                if Some(parameters) == attributes.cryptographic_parameters {
                    attributes.cryptographic_parameters = None;
                }
            }
            Attribute::CryptographicDomainParameters(domain_parameters) => {
                if Some(domain_parameters) == attributes.cryptographic_domain_parameters {
                    attributes.cryptographic_domain_parameters = None;
                }
            }
            Attribute::CryptographicUsageMask(usage_mask) => {
                if Some(usage_mask) == attributes.cryptographic_usage_mask {
                    attributes.cryptographic_usage_mask = None;
                }
            }
            Attribute::Links(requested_links) => {
                for requested_link in &requested_links {
                    attributes.remove_link(requested_link.link_type);
                }
            }
            Attribute::VendorAttributes(vendor_attributes) => {
                for vendor_attribute in &vendor_attributes {
                    attributes.remove_vendor_attribute(
                        &vendor_attribute.vendor_identification,
                        &vendor_attribute.attribute_name,
                    );
                }
            }
        }
    };

    if let Some(attribute_references) = request.attribute_references {
        for attribute_reference in attribute_references {
            match attribute_reference {
                AttributeReference::Standard(tag) => match tag {
                    Tag::ActivationDate => {
                        attributes.activation_date = None;
                    }
                    Tag::CryptographicAlgorithm => {
                        attributes.cryptographic_algorithm = None;
                    }
                    Tag::CryptographicLength => {
                        attributes.cryptographic_length = None;
                    }
                    Tag::CryptographicParameters => {
                        attributes.cryptographic_parameters = None;
                    }
                    Tag::CryptographicDomainParameters => {
                        attributes.cryptographic_domain_parameters = None;
                    }
                    Tag::CryptographicUsageMask => {
                        attributes.cryptographic_usage_mask = None;
                    }
                    Tag::LinkType => {
                        attributes.link = None;
                    }
                    Tag::VendorExtension => {
                        attributes.vendor_attributes = None;
                    }
                    _ => {}
                },
                AttributeReference::Vendor(_) => attributes.vendor_attributes = None,
            }
        }
    }

    let tags = kms.database.retrieve_tags(owm.id(), params).await?;

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        *object_attributes = attributes.clone();
    }

    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags), params)
        .await?;

    Ok(DeleteAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
