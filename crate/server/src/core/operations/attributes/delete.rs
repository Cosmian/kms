use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation,
    kmip_attributes::Attribute,
    kmip_objects::{Object, PrivateKey, PublicKey, SecretData, SymmetricKey},
    kmip_operations::{DeleteAttribute, DeleteAttributeResponse},
    kmip_types::{AttributeReference, Tag, UniqueIdentifier},
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn delete_attribute(
    kms: &KMS,
    request: DeleteAttribute,
    user: &str,
) -> KResult<DeleteAttributeResponse> {
    trace!("{}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Delete Attribute: the unique identifier must be a string")?;

    let mut owm = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::DeleteAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes().to_owned();

    if let Some(attribute) = request.current_attribute {
        match_delete_attribute! {
            attribute, attributes,
            simple {
                ActivationDate => activation_date,
                AlternativeName => alternative_name,
                AlwaysSensitive => always_sensitive,
                ApplicationSpecificInformation => application_specific_information,
                ArchiveDate => archive_date,
                AttributeIndex => attribute_index,
                CertificateAttributes => certificate_attributes,
                CertificateLength => certificate_length,
                CertificateType => certificate_type,
                Comment => comment,
                CompromiseDate => compromise_date,
                CompromiseOccurrenceDate => compromise_occurrence_date,
                ContactInformation => contact_information,
                Critical => critical,
                CryptographicAlgorithm => cryptographic_algorithm,
                CryptographicDomainParameters => cryptographic_domain_parameters,
                CryptographicParameters => cryptographic_parameters,
                CryptographicUsageMask => cryptographic_usage_mask,
                DeactivationDate => deactivation_date,
                Description => description,
                DestroyDate => destroy_date,
                Digest => digest,
                DigitalSignatureAlgorithm => digital_signature_algorithm,
                Extractable => extractable,
                Fresh => fresh,
                InitialDate => initial_date,
                KeyFormatType => key_format_type,
                KeyValueLocation => key_value_location,
                KeyValuePresent => key_value_present,
                LastChangeDate => last_change_date,
                LeaseTime => lease_time,
                NeverExtractable => never_extractable,
                NistKeyType => nist_key_type,
                ObjectGroup => object_group,
                ObjectGroupMember => object_group_member,
                ObjectType => object_type,
                OpaqueDataType => opaque_data_type,
                OriginalCreationDate => original_creation_date,
                Pkcs12FriendlyName => pkcs_12_friendly_name,
                ProcessStartDate => process_start_date,
                ProtectStopDate => protect_stop_date,
                ProtectionLevel => protection_level,
                ProtectionPeriod => protection_period,
                ProtectionStorageMasks => protection_storage_masks,
                QuantumSafe => quantum_safe,
                RandomNumberGenerator => random_number_generator,
                RevocationReason => revocation_reason,
                RotateDate => rotate_date,
                RotateGeneration => rotate_generation,
                RotateInterval => rotate_interval,
                RotateLatest => rotate_latest,
                RotateName => rotate_name,
                RotateOffset => rotate_offset,
                Sensitive => sensitive,
                ShortUniqueIdentifier => short_unique_identifier,
                State => state,
                UniqueIdentifier => unique_identifier,
                UsageLimits => usage_limits,
                X509CertificateIdentifier => x_509_certificate_identifier,
                X509CertificateIssuer => x_509_certificate_issuer,
                X509CertificateSubject => x_509_certificate_subject,
            }
            custom {
                Attribute::CryptographicLength(length) => {
                    if Some(length) == attributes.cryptographic_length {
                        attributes.cryptographic_length = None;
                        match owm.object_mut() {
                            Object::SymmetricKey(SymmetricKey { key_block })
                            | Object::PrivateKey(PrivateKey { key_block })
                            | Object::PublicKey(PublicKey { key_block })
                            | Object::SecretData(SecretData { key_block, .. }) => {
                                key_block.cryptographic_length = None;
                            }
                            _ => {}
                        }
                    }
                }
                Attribute::Link(requested_link) => {
                    attributes.remove_link(requested_link.link_type);
                }
                Attribute::Name(name) => {
                    attributes.name = attributes
                        .name
                        .map(|v| v.into_iter().filter(|n| n != &name).collect());
                }
                Attribute::VendorAttribute(vendor_attribute) => {
                    attributes.remove_vendor_attribute(
                        &vendor_attribute.vendor_identification,
                        &vendor_attribute.attribute_name,
                    );
                }
            }
        }
    }

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
                    Tag::Name => {
                        attributes.name = None;
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

    let tags = kms.database.retrieve_tags(owm.id()).await?;

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        *object_attributes = attributes.clone();
    }

    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags))
        .await?;

    Ok(DeleteAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
