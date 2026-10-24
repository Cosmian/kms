use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::{Attribute, Attributes},
        kmip_operations::{DeleteAttribute, DeleteAttributeResponse},
        kmip_types::{AttributeReference, LinkedObjectIdentifier, Tag, UniqueIdentifier},
    },
    time_normalize,
};
use cosmian_logger::trace;

use super::policy::{
    check_grant, check_read_only, check_vendor_attribute, is_server_vendor_attribute,
    read_only_error,
};
use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::from_request},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

pub(crate) async fn delete_attribute(
    kms: &KMS,
    request: DeleteAttribute,
    user: &UserId,
) -> KResult<DeleteAttributeResponse> {
    trace!("DeleteAttribute request");

    // there must be an identifier
    let object_handle = from_request(request.unique_identifier.as_ref(), "Delete Attribute")?;

    // Read-only guards — server-managed attributes cannot be deleted by the user.
    if let Some(attribute) = &request.current_attribute {
        check_read_only(attribute.tag(), KmipOperation::DeleteAttribute)?;
        check_vendor_attribute(attribute, KmipOperation::DeleteAttribute)?;
    }
    for reference in request.attribute_references.iter().flatten() {
        match reference {
            AttributeReference::Standard(tag) => {
                check_read_only(Some(*tag), KmipOperation::DeleteAttribute)?;
            }
            AttributeReference::Vendor(vendor_ref) => {
                if is_server_vendor_attribute(
                    &vendor_ref.vendor_identification,
                    &vendor_ref.attribute_name,
                ) {
                    return Err(read_only_error(KmipOperation::DeleteAttribute));
                }
            }
        }
    }

    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::DeleteAttribute,
        kms,
        user,
    ))
    .await?;
    let deleted_tags =
        request
            .current_attribute
            .as_ref()
            .map(Attribute::tag)
            .into_iter()
            .chain(request.attribute_references.iter().flatten().map(
                |reference| match reference {
                    AttributeReference::Standard(tag) => Some(*tag),
                    AttributeReference::Vendor(_) => None,
                },
            ));
    for tag in deleted_tags {
        check_grant(kms, &owm, user, KmipOperation::DeleteAttribute, tag).await?;
    }
    let (id, mut object, mut attributes) = Arc::unwrap_or_clone(owm).into_parts();
    trace!("Retrieved object for DeleteAttribute");

    // Snapshot the attribute set so the response can echo the attribute that was
    // actually removed: KMIP 1.4 §4.16 Table 205 requires the deleted `Attribute`
    // in the response payload (KMIP 2.1 §6.1.13 Table 203 requires only the UID).
    let attributes_before = attributes.clone();
    let mut removed_attribute: Option<Attribute> = None;

    let current = request.current_attribute.clone();
    if let Some(attribute) = current {
        match_delete_attribute! {
            attribute, attributes,
            simple {
                ActivationDate => activation_date,
                AlternativeName => alternative_name,
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
                ProtectionStorageMask => protection_storage_masks,
                QuantumSafe => quantum_safe,
                RandomNumberGenerator => random_number_generator,
                RevocationReason => revocation_reason,
                RotateAutomatic => rotate_automatic,
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
                Attribute::AlwaysSensitive(_)
                | Attribute::CryptographicLength(_)
                | Attribute::Digest(_) => {
                    // Defensive: already refused by `check_read_only`.
                    return Err(read_only_error(KmipOperation::DeleteAttribute));
                }
                Attribute::Link(requested_link) => {
                    if let Some(links) = attributes.link.as_mut() {
                        // An empty identifier (sent by the Web UI) selects every link of that type.
                        let any_target = matches!(
                            &requested_link.linked_object_identifier,
                            LinkedObjectIdentifier::TextString(s) if s.is_empty()
                        );
                        links.retain(|l| {
                            !(l.link_type == requested_link.link_type
                                && (any_target
                                    || l.linked_object_identifier
                                        == requested_link.linked_object_identifier))
                        });
                        if links.is_empty() {
                            attributes.link = None;
                        }
                    }
                }
                Attribute::Name(name) => {
                    if let Some(names) = &mut attributes.name {
                        names.retain(|n| n != &name);
                    }
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
    if request.current_attribute.is_some() && attributes == attributes_before {
        // KMIP 2.1 §6.1.13: a Current Attribute matching no instance is an error.
        let reason = if Vec::<Attribute>::from(attributes_before.clone())
            .iter()
            .any(|a| a.tag() == request.current_attribute.as_ref().and_then(Attribute::tag))
        {
            ErrorReason::Attribute_Instance_Not_Found
        } else {
            ErrorReason::Attribute_Not_Found
        };
        return Err(KmsError::Kmip21Error(
            reason,
            "DeleteAttribute: no matching attribute to delete".to_owned(),
        ));
    }
    let before_references = attributes.clone();
    if let Some(attribute_references) = request.attribute_references {
        for attribute_reference in attribute_references {
            match attribute_reference {
                AttributeReference::Standard(tag) => {
                    match_delete_attribute_by_tag! {
                        tag, attributes,
                        simple {
                            ActivationDate => activation_date,
                            AlternativeName => alternative_name,
                            ApplicationSpecificInformation => application_specific_information,
                            ArchiveDate => archive_date,
                            CertificateAttributes => certificate_attributes,
                            CertificateType => certificate_type,
                            Comment => comment,
                            CompromiseDate => compromise_date,
                            CompromiseOccurrenceDate => compromise_occurrence_date,
                            ContactInformation => contact_information,
                            CryptographicAlgorithm => cryptographic_algorithm,
                            CryptographicDomainParameters => cryptographic_domain_parameters,
                            CryptographicParameters => cryptographic_parameters,
                            CryptographicUsageMask => cryptographic_usage_mask,
                            DeactivationDate => deactivation_date,
                            Description => description,
                            DestroyDate => destroy_date,
                            DigitalSignatureAlgorithm => digital_signature_algorithm,
                            Extractable => extractable,
                            KeyFormatType => key_format_type,
                            KeyValueLocation => key_value_location,
                            KeyValuePresent => key_value_present,
                            LeaseTime => lease_time,
                            NISTKeyType => nist_key_type,
                            ObjectGroup => object_group,
                            ObjectGroupMember => object_group_member,
                            OpaqueDataType => opaque_data_type,
                            PKCS12FriendlyName => pkcs_12_friendly_name,
                            ProcessStartDate => process_start_date,
                            ProtectStopDate => protect_stop_date,
                            ProtectionLevel => protection_level,
                            ProtectionPeriod => protection_period,
                            ProtectionStorageMask => protection_storage_masks,
                            QuantumSafe => quantum_safe,
                            RandomNumberGenerator => random_number_generator,
                            RevocationReason => revocation_reason,
                            RotateInterval => rotate_interval,
                            RotateName => rotate_name,
                            RotateOffset => rotate_offset,
                            Sensitive => sensitive,
                            ShortUniqueIdentifier => short_unique_identifier,
                            UsageLimits => usage_limits,
                            X509CertificateIdentifier => x_509_certificate_identifier,
                            X509CertificateIssuer => x_509_certificate_issuer,
                            X509CertificateSubject => x_509_certificate_subject,
                        }
                        custom {
                            Tag::LinkType | Tag::Link => {
                                attributes.link = None;
                            }
                            Tag::Name => {
                                attributes.name = None;
                            }
                            Tag::VendorExtension => {
                                // Server-owned custom attributes survive a wipe of the others
                                if let Some(vendor_attributes) = attributes.vendor_attributes.as_mut() {
                                    vendor_attributes.retain(|va| {
                                        is_server_vendor_attribute(
                                            &va.vendor_identification,
                                            &va.attribute_name,
                                        )
                                    });
                                    if vendor_attributes.is_empty() {
                                        attributes.vendor_attributes = None;
                                    }
                                }
                            }
                            unsupported => {
                                return Err(KmsError::Kmip21Error(
                                    ErrorReason::Invalid_Field,
                                    format!(
                                        "DeleteAttribute: unsupported attribute {unsupported:?}"
                                    ),
                                ));
                            }
                        }
                    }
                }
                AttributeReference::Vendor(vendor_ref) => {
                    if let Some(vendor_attributes) = attributes.vendor_attributes.as_mut() {
                        if let Some(found) = vendor_attributes.iter().find(|va| {
                            va.vendor_identification == vendor_ref.vendor_identification
                                && va.attribute_name == vendor_ref.attribute_name
                        }) {
                            removed_attribute = Some(Attribute::VendorAttribute(found.clone()));
                        }
                        vendor_attributes.retain(|va| {
                            !(va.vendor_identification == vendor_ref.vendor_identification
                                && va.attribute_name == vendor_ref.attribute_name)
                        });
                        if vendor_attributes.is_empty() {
                            attributes.vendor_attributes = None;
                        }
                    }
                }
            }
        }
    }

    if attributes == before_references && attributes == attributes_before {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Attribute_Not_Found,
            "DeleteAttribute: the attribute is not set on the object".to_owned(),
        ));
    }
    let echoed_attribute =
        removed_attribute.or_else(|| deleted_attribute(&attributes_before, &attributes));
    attributes.last_change_date = Some(time_normalize()?);

    let tags = kms.database.retrieve_tags(&id).await?;

    if let Ok(object_attributes) = object.attributes_mut() {
        object_attributes.clone_from(&attributes);
    }

    kms.database
        .update_object(&id, &object, &attributes, Some(&tags))
        .await?;

    Ok(DeleteAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(id),
        echoed_attribute,
    })
}

/// Returns the attribute that `after` no longer carries but `before` did.
///
/// KMIP 1.4 §4.16 Table 205 requires a Delete Attribute response to name the
/// deleted attribute. Diffing the two attribute sets keeps this generic: no
/// per-tag bookkeeping is needed and it stays correct as new attributes are added.
fn deleted_attribute(before: &Attributes, after: &Attributes) -> Option<Attribute> {
    // Only convert before into attributes list, check after field-by-field or contains
    let after_attributes: Vec<Attribute> = after.clone().into();
    Vec::<Attribute>::from(before.clone())
        .into_iter()
        .find(|candidate| !after_attributes.contains(candidate))
}
