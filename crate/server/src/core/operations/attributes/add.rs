use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attribute,
            kmip_objects::ObjectType,
            kmip_operations::{AddAttribute, AddAttributeResponse},
            kmip_types::UniqueIdentifier,
        },
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, trace};

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub(crate) async fn add_attribute(
    kms: &KMS,
    request: AddAttribute,
    user: &str,
) -> KResult<AddAttributeResponse> {
    trace!("{}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_str()
        .context("Add Attribute: the unique identifier must be a string")?;

    // Read-only guard — these attributes are server-managed.
    match &request.new_attribute {
        Attribute::RotateAutomatic(_)
        | Attribute::RotateGeneration(_)
        | Attribute::RotateDate(_)
        | Attribute::RotateLatest(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "DENIED: this attribute is server-managed and cannot be added by the user"
                    .to_owned(),
            ));
        }
        Attribute::RotateName(name) if name.contains('@') => {
            return Err(KmsError::InvalidRequest(
                "AddAttribute: rotate_name must not contain '@' (reserved for keyset versioning)"
                    .to_owned(),
            ));
        }
        _ => {}
    }

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::AddAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes_mut().clone();

    // Check if the attribute is allowed to be set
    match_add_attribute! {
        request.new_attribute, attributes,
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
            RotateAutomatic => rotate_automatic,
            RotateDate => rotate_date,
            RotateGeneration => rotate_generation,
            RotateInterval => rotate_interval,
            RotateLatest => rotate_latest,
            RotateName => rotate_name,
            RotateOffset => rotate_offset,
            ShortUniqueIdentifier => short_unique_identifier,
            UsageLimits => usage_limits,
            X509CertificateIdentifier => x_509_certificate_identifier,
        }
        custom {
            Attribute::Link(link) => {
                trace!("Link: {}", link);
                if attributes.get_link(link.link_type).is_some() {
                    return Err(KmsError::InvalidRequest("Link already exists".to_owned()));
                }
                attributes.set_link(link.link_type, link.linked_object_identifier);
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                trace!("Vendor Attribute: {}", vendor_attribute);
                // For KMIP 1.x deprecated attributes (e.g. OperationPolicyName)
                // that are stored as VendorAttributes with vendor_identification="KMIP1",
                // allow overwrite since the attribute may already exist from the
                // Create template. VAST sends OPN both in Create and via AddAttribute.
                let is_kmip1_compat =
                    vendor_attribute.vendor_identification == "KMIP1";
                if !is_kmip1_compat
                    && attributes
                        .get_vendor_attribute_value(
                            &vendor_attribute.vendor_identification,
                            &vendor_attribute.attribute_name,
                        )
                        .is_some()
                {
                    return Err(KmsError::InvalidRequest(
                        "Vendor Attribute already exists".to_owned(),
                    ));
                }
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
            Attribute::Name(name) => {
                trace!("Name: {name}");
                let names = attributes.name.get_or_insert(vec![]);
                if names.iter().any(|n| n == &name) {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Non_Unique_Name_Attribute,
                        "DENIED".to_owned(),
                    ));
                }
                names.push(name);
            }
            Attribute::Description(description) => {
                trace!("Description: {:?}", description);
                if attributes.description.is_some() {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Attribute_Single_Valued,
                        "DENIED".to_owned(),
                    ));
                }
                attributes.description = Some(description);
            }
            Attribute::Sensitive(sensitive) => {
                trace!("Sensitive: {:?}", sensitive);
                if attributes.sensitive.is_some() {
                    return Err(KmsError::InvalidRequest(
                        "Sensitive already exists".to_owned(),
                    ));
                }
                attributes.sensitive = sensitive.then_some(true);
            }
            Attribute::State(_state) => {
                return Err(KmsError::InvalidRequest(
                    "Attribute: State cannot be modified. Use Revoke and Destroy to change the \
                     object state"
                        .to_owned(),
                ));
            }
        }
    }

    // update the last change date
    attributes.last_change_date = Some(time_normalize()?);

    let tags = kms.database.retrieve_tags(owm.id()).await?;

    match owm.object().object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            let object_attributes = owm.object_mut().attributes_mut()?;
            *object_attributes = attributes.clone();
            debug!("Set Object Attribute: {}", object_attributes);
        }
        _ => {
            trace!(
                "Attribute: Object type {:?} does not have attributes (nor key block)",
                owm.object().object_type()
            );
        }
    }

    debug!("Add Attribute: {}", attributes);
    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags))
        .await?;

    Ok(AddAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
