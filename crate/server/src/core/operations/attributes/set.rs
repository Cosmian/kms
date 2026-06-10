use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attribute,
        kmip_objects::ObjectType,
        kmip_operations::{SetAttribute, SetAttributeResponse},
        kmip_types::UniqueIdentifier,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, trace};

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn set_attribute(
    kms: &KMS,
    request: SetAttribute,
    user: &str,
) -> KResult<SetAttributeResponse> {
    debug!("{request}");

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Set Attribute: the unique identifier must be a string")?;

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::SetAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("Set Attribute: Retrieved target object");

    let mut attributes = owm.attributes_mut().clone();

    // Check if the attribute is allowed to be set
    match_set_attribute! {
        "SetAttribute", request.new_attribute, attributes,
        simple {
            ActivationDate => activation_date,
            CryptographicAlgorithm => cryptographic_algorithm,
            CryptographicLength => cryptographic_length,
            CryptographicParameters => cryptographic_parameters,
            CryptographicDomainParameters => cryptographic_domain_parameters,
            CryptographicUsageMask => cryptographic_usage_mask,
            Digest => digest,
            DeactivationDate => deactivation_date,
            ObjectGroup => object_group,
            ContactInformation => contact_information,
            ObjectType => object_type,
            UniqueIdentifier => unique_identifier,
            X509CertificateSubject => x_509_certificate_subject,
            X509CertificateIssuer => x_509_certificate_issuer,
            AlternativeName => alternative_name,
            AlwaysSensitive => always_sensitive,
            ApplicationSpecificInformation => application_specific_information,
            ArchiveDate => archive_date,
            AttributeIndex => attribute_index,
            CertificateAttributes => certificate_attributes,
            CertificateType => certificate_type,
            CertificateLength => certificate_length,
            Comment => comment,
            CompromiseDate => compromise_date,
            CompromiseOccurrenceDate => compromise_occurrence_date,
            Critical => critical,
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
            ObjectGroupMember => object_group_member,
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
            UsageLimits => usage_limits,
            X509CertificateIdentifier => x_509_certificate_identifier,
        }
        custom {
            Attribute::Link(link) => {
                trace!("Set Attribute: Link: {}", link.linked_object_identifier);
                attributes.set_link(link.link_type, link.linked_object_identifier);
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                trace!("Set Attribute: Vendor Attribute: {}", vendor_attribute);
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
            Attribute::Name(name) => {
                trace!("Set Attribute: Name: {}", name);
                let names = attributes.name.get_or_insert(vec![]);
                if !names.iter().any(|n| n == &name) {
                    names.push(name);
                }
            }
            Attribute::State(_state) => {
                return Err(KmsError::InvalidRequest(
                    "Set Attribute: State is server-managed and cannot be set directly. Use \
                     Revoke and Destroy to change the object state"
                        .to_owned(),
                ));
            }
        }
    }

    let tags = kms.database.retrieve_tags(owm.id()).await?;

    match owm.object().object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            // For wrapped keys, `attributes_mut()` returns an error because the key
            // block holds a ByteString (ciphertext), not a Structure. In that case,
            // skip the embedded key-block update; the attribute is persisted in the
            // metadata column by `update_object` below.
            if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
                *object_attributes = attributes.clone();
                debug!("Set Object Attribute: {}", object_attributes);
            }
        }
        _ => {
            trace!(
                "Set Attribute: Object type {:?} does not have attributes (nor key block)",
                owm.object().object_type()
            );
        }
    }

    debug!("Set Attribute: {}", attributes);
    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags))
        .await?;

    Ok(SetAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
