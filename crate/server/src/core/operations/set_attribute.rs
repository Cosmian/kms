use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{SetAttribute, SetAttributeResponse},
    kmip_types::{Attribute, UniqueIdentifier},
    KmipOperation,
};
use cosmian_kms_server_database::{ExtraStoreParams, ObjectWithMetadata};
use tracing::{debug, trace};

use crate::{
    core::{retrieve_object_utils::retrieve_object_for_operation, KMS},
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn set_attribute(
    kms: &KMS,
    request: SetAttribute,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<SetAttributeResponse> {
    trace!("Set attribute: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Set Attribute: the unique identifier must be a string")?;

    let mut owm: ObjectWithMetadata =
        retrieve_object_for_operation(uid_or_tags, KmipOperation::GetAttributes, kms, user, params)
            .await?;
    trace!("Set Attribute: Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes_mut().clone();

    match request.new_attribute {
        Attribute::ActivationDate(activation_date) => {
            trace!("Set Attribute: Activation Date: {:?}", activation_date);
            attributes.activation_date = Some(activation_date);
        }
        Attribute::CryptographicAlgorithm(cryptographic_algorithm) => {
            trace!(
                "Set Attribute: Cryptographic Algorithm: {:?}",
                cryptographic_algorithm
            );
            attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
        }
        Attribute::CryptographicLength(length) => {
            trace!("Set Attribute: Cryptographic Length: {:?}", length);
            attributes.cryptographic_length = Some(length);
        }
        Attribute::CryptographicParameters(parameters) => {
            trace!("Set Attribute: Cryptographic Parameters: {:?}", parameters);
            attributes.cryptographic_parameters = Some(parameters);
        }
        Attribute::CryptographicDomainParameters(domain_parameters) => {
            trace!(
                "Set Attribute: Cryptographic Domain Parameters: {:?}",
                domain_parameters
            );
            attributes.cryptographic_domain_parameters = Some(domain_parameters);
        }
        Attribute::CryptographicUsageMask(usage_mask) => {
            trace!("Set Attribute: Cryptographic Usage Mask: {:?}", usage_mask);
            attributes.cryptographic_usage_mask = Some(usage_mask);
        }
        Attribute::Links(links) => {
            trace!("Set Attribute: Link: {:?}", links);
            for link in &links {
                attributes.set_link(link.link_type, link.linked_object_identifier.clone());
            }
        }
        Attribute::VendorAttributes(vendor_attributes) => {
            trace!("Set Attribute: Vendor Attributes: {:?}", vendor_attributes);
            for vendor_attribute in vendor_attributes {
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
        }
    }

    let tags = kms.database.retrieve_tags(owm.id(), params).await?;

    match owm.object().object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            let object_attributes = owm.object_mut().attributes_mut()?;
            *object_attributes = attributes.clone();
            debug!("Set Object Attribute: {:?}", object_attributes);
        }
        _ => {
            trace!(
                "Set Attribute: Object type {:?} does not have attributes (nor key block)",
                owm.object().object_type()
            );
        }
    }

    debug!("Set Attribute: {:?}", attributes);
    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags), params)
        .await?;

    Ok(SetAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
