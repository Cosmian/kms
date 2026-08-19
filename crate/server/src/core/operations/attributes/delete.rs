use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::{Object, PrivateKey, PublicKey, SecretData, SymmetricKey},
        kmip_operations::{DeleteAttribute, DeleteAttributeResponse},
        kmip_types::{AttributeReference, Tag, UniqueIdentifier},
    },
};
use cosmian_logger::trace;

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
    trace!("{}", serde_json::to_string(&request)?);

    // there must be an identifier
    let object_handle = from_request(request.unique_identifier.as_ref(), "Delete Attribute")?;

    let mut owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::DeleteAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes().to_owned();
    // Snapshot the attribute set so the response can echo the attribute that was
    // actually removed: KMIP 1.4 §4.16 Table 205 requires the deleted `Attribute`
    // in the response payload (KMIP 2.1 §6.1.13 Table 203 requires only the UID).
    let attributes_before = attributes.clone();
    // The attribute actually removed, echoed back in the response.
    let mut removed_attribute: Option<Attribute> = None;

    if let Some(attribute) = request.current_attribute {
        // Read-only guard — these attributes are server-managed.
        match &attribute {
            Attribute::AlwaysSensitive(_)
            | Attribute::RotateAutomatic(_)
            | Attribute::RotateGeneration(_)
            | Attribute::RotateDate(_)
            | Attribute::RotateLatest(_) => {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Attribute_Read_Only,
                    "DENIED: this attribute is server-managed and cannot be deleted by the user"
                        .to_owned(),
                ));
            }
            _ => {}
        }
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
                Attribute::AlwaysSensitive(_) => {
                    // Defensive: rejected earlier by the read-only guard (KMIP 2.1 §4.3).
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Attribute_Read_Only,
                        "DENIED: AlwaysSensitive is server-managed and cannot be deleted by the \
                         user"
                            .to_owned(),
                    ));
                }
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
                AttributeReference::Standard(tag) => {
                    // Read-only guard — every tag below is marked
                    // "Deletable by client: No" in its KMIP Attribute Rules table.
                    if matches!(
                        tag,
                        // KMIP 1.4 §3.1  — Unique Identifier
                        Tag::UniqueIdentifier
                        // KMIP 1.4 §3.3  — Object Type
                            | Tag::ObjectType
                        // KMIP 1.4 §3.5  — Cryptographic Length
                            | Tag::CryptographicLength
                        // KMIP 1.4 §3.9  — Certificate Length
                            | Tag::CertificateLength
                        // KMIP 1.4 §3.17 — Digest
                            | Tag::Digest
                        // KMIP 1.4 §3.22 — State
                            | Tag::State
                        // KMIP 1.4 §3.23 — Initial Date
                            | Tag::InitialDate
                        // KMIP 1.4 §3.34 — Fresh
                            | Tag::Fresh
                        // KMIP 1.4 §3.38 — Last Change Date
                            | Tag::LastChangeDate
                        // KMIP 1.4 §3.43 — Original Creation Date
                            | Tag::OriginalCreationDate
                        // KMIP 1.4 §3.49 — Always Sensitive
                            | Tag::AlwaysSensitive
                        // KMIP 1.4 §3.51 — Never Extractable
                            | Tag::NeverExtractable
                        // Cosmian keyset rotation metadata is server-managed.
                            | Tag::RotateAutomatic
                            | Tag::RotateGeneration
                            | Tag::RotateDate
                            | Tag::RotateLatest
                    ) {
                        return Err(KmsError::Kmip21Error(
                            ErrorReason::Attribute_Read_Only,
                            "DENIED: this attribute is server-managed and cannot be deleted by \
                             the user"
                                .to_owned(),
                        ));
                    }
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
                            ProtectionStorageMasks => protection_storage_masks,
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
                            Tag::LinkType => {
                                attributes.link = None;
                            }
                            Tag::Name => {
                                attributes.name = None;
                            }
                            Tag::VendorExtension => {
                                attributes.vendor_attributes = None;
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

    let tags = kms.database.retrieve_tags(owm.id()).await?;

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        *object_attributes = attributes.clone();
    }

    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags))
        .await?;

    Ok(DeleteAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        echoed_attribute: removed_attribute
            .or_else(|| deleted_attribute(&attributes_before, &attributes)),
    })
}

/// Returns the attribute that `after` no longer carries but `before` did.
///
/// KMIP 1.4 §4.16 Table 205 requires a Delete Attribute response to name the
/// deleted attribute. Diffing the two attribute sets keeps this generic: no
/// per-tag bookkeeping is needed and it stays correct as new attributes are added.
fn deleted_attribute(before: &Attributes, after: &Attributes) -> Option<Attribute> {
    let after_attributes: Vec<Attribute> = after.clone().into();
    Vec::<Attribute>::from(before.clone())
        .into_iter()
        .find(|candidate| !after_attributes.contains(candidate))
}
