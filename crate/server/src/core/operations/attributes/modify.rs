use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attribute,
            kmip_objects::ObjectType,
            kmip_operations::{ModifyAttribute, ModifyAttributeResponse},
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

/// KMIP 2.1 `ModifyAttribute` operation.
///
/// Modifies or sets a single attribute on an existing managed object, enforcing
/// all KMIP lifecycle rules:
///
/// - Read-only attributes (`State`, `CertificateLength`) are rejected.
/// - Modifying `ActivationDate` is only allowed on objects in the **Pre-Active** state,
///   per KMIP spec §3.22. If the new date is in the past or present the object
///   automatically transitions to the **Active** state.
/// - All other attributes are applied and persisted immediately.
///
/// Permission checks and uid/tags resolution are performed via
/// `retrieve_object_for_operation` (same as `SetAttribute` and `Activate`).
pub(crate) async fn modify_attribute(
    kms: &KMS,
    request: ModifyAttribute,
    user: &str,
) -> KResult<ModifyAttributeResponse> {
    debug!("{request}");

    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ModifyAttribute: the unique identifier must be a string")?;

    // Read-only guard — must be checked before the DB round-trip.
    match &request.new_attribute {
        Attribute::AlwaysSensitive(_)
        | Attribute::State(_)
        | Attribute::CertificateLength(_)
        | Attribute::RotateGeneration(_)
        | Attribute::RotateDate(_)
        | Attribute::RotateLatest(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "DENIED: this attribute is server-managed and cannot be modified by the user"
                    .to_owned(),
            ));
        }
        Attribute::RotateName(name) if name.contains('@') => {
            return Err(KmsError::InvalidRequest(
                "ModifyAttribute: rotate_name must not contain '@' (reserved for keyset versioning)"
                    .to_owned(),
            ));
        }
        _ => {}
    }

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::ModifyAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("ModifyAttribute: retrieved target object {}", owm.id());

    // For ActivationDate, KMIP spec §3.22 requires the object to be in Pre-Active state.
    // The transition Pre-Active → Active is triggered automatically when the new date is
    // in the past or equals the current time.
    let mut activate = false;
    if let Attribute::ActivationDate(_) = &request.new_attribute {
        let current_state = owm.state();
        if current_state != State::PreActive {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                format!(
                    "ModifyAttribute: ActivationDate can only be modified on a Pre-Active object \
                     (current state: {current_state:?})"
                ),
            ));
        }
    }

    let mut attributes = owm.attributes_mut().clone();

    match_set_attribute! {
        "ModifyAttribute", request.new_attribute, attributes,
        simple {
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
            Attribute::AlwaysSensitive(_) => {
                // Defensive: rejected earlier by the read-only guard (KMIP 2.1 §4.3).
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Attribute_Read_Only,
                    "DENIED: AlwaysSensitive is server-managed and cannot be modified by the user"
                        .to_owned(),
                ));
            }
            Attribute::Sensitive(sensitive) => {
                // Setting Sensitive also (re)computes the server-managed
                // AlwaysSensitive attribute (KMIP 2.1 §4.3).
                trace!("ModifyAttribute: Sensitive: {:?}", sensitive);
                attributes.apply_sensitive(sensitive);
            }
            Attribute::ActivationDate(activation_date) => {
                trace!("ModifyAttribute: ActivationDate: {:?}", activation_date);
                attributes.activation_date = Some(activation_date);
                // Per KMIP spec §3.22: if the new date is in the past or present, transition to Active.
                let now = time_normalize()?;
                if activation_date <= now {
                    attributes.state = Some(State::Active);
                    activate = true;
                }
            }
            Attribute::Link(link) => {
                trace!("ModifyAttribute: Link: {}", link.linked_object_identifier);
                attributes.set_link(link.link_type, link.linked_object_identifier);
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                trace!("ModifyAttribute: VendorAttribute: {}", vendor_attribute);
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
            Attribute::Name(name) => {
                trace!("ModifyAttribute: Name: {}", name);
                match attributes.name.as_mut() {
                    Some(names) if !names.is_empty() => {
                        if let Some(first) = names.get_mut(0) {
                            *first = name;
                        }
                    }
                    Some(names) => {
                        names.push(name);
                    }
                    None => {
                        attributes.name = Some(vec![name]);
                    }
                }
            }
            Attribute::State(_state) => {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Attribute_Read_Only,
                    "ModifyAttribute: State is read-only".to_owned(),
                ));
            }
        }
    }

    let tags = kms.database.retrieve_tags(owm.id()).await?;

    // Write modified attributes back into the embedded key-block attributes for key objects.
    // For objects whose key value is a raw ByteString (e.g. opaque SecretData), the key
    // block has no Structure variant and cannot store embedded attributes.  In that case we
    // skip the embedding — the attributes are persisted independently via update_object below.
    match owm.object().object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
                *object_attributes = attributes.clone();
            }
        }
        _ => {}
    }

    debug!("ModifyAttribute: persisting attributes for {}", owm.id());
    kms.database
        .update_object(owm.id(), owm.object(), &attributes, Some(&tags))
        .await?;

    // Persist the state transition separately (dedicated DB column).
    if activate {
        kms.database.update_state(owm.id(), State::Active).await?;
    }

    Ok(ModifyAttributeResponse {
        unique_identifier: Some(UniqueIdentifier::TextString(owm.id().to_owned())),
        echoed_attribute: None,
    })
}
