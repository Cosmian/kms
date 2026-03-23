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
        Attribute::State(_) | Attribute::CertificateLength(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "DENIED".to_owned(),
            ));
        }
        _ => {}
    }

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::GetAttributes,
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

    match request.new_attribute {
        Attribute::ActivationDate(activation_date) => {
            trace!("ModifyAttribute: Activation Date: {}", activation_date);
            attributes.activation_date = Some(activation_date);
            // Per KMIP spec §3.22: if the new date is in the past or present, transition to Active.
            let now = time_normalize()?;
            if activation_date <= now {
                attributes.state = Some(State::Active);
                activate = true;
            }
        }
        Attribute::CryptographicAlgorithm(cryptographic_algorithm) => {
            trace!(
                "ModifyAttribute: Cryptographic Algorithm: {}",
                cryptographic_algorithm
            );
            attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
        }
        Attribute::CryptographicLength(length) => {
            trace!("ModifyAttribute: Cryptographic Length: {}", length);
            attributes.cryptographic_length = Some(length);
        }
        Attribute::CryptographicParameters(parameters) => {
            trace!("ModifyAttribute: Cryptographic Parameters: {}", parameters);
            attributes.cryptographic_parameters = Some(parameters);
        }
        Attribute::CryptographicDomainParameters(domain_parameters) => {
            trace!(
                "ModifyAttribute: Cryptographic Domain Parameters: {}",
                domain_parameters
            );
            attributes.cryptographic_domain_parameters = Some(domain_parameters);
        }
        Attribute::CryptographicUsageMask(usage_mask) => {
            trace!("ModifyAttribute: Cryptographic Usage Mask: {}", usage_mask);
            attributes.cryptographic_usage_mask = Some(usage_mask);
        }
        Attribute::Digest(digest) => {
            trace!("ModifyAttribute: Digest: {}", digest);
            attributes.digest = Some(digest);
        }
        Attribute::Link(link) => {
            trace!("ModifyAttribute: Link: {}", link.linked_object_identifier);
            attributes.set_link(link.link_type, link.linked_object_identifier);
        }
        Attribute::VendorAttribute(vendor_attribute) => {
            trace!("ModifyAttribute: Vendor Attribute: {}", vendor_attribute);
            attributes.set_vendor_attribute(
                &vendor_attribute.vendor_identification,
                &vendor_attribute.attribute_name,
                vendor_attribute.attribute_value,
            );
        }
        Attribute::DeactivationDate(deactivation_date) => {
            trace!("ModifyAttribute: Deactivation Date: {}", deactivation_date);
            attributes.deactivation_date = Some(deactivation_date);
        }
        Attribute::ObjectGroup(object_group) => {
            trace!("ModifyAttribute: Object Group: {}", object_group);
            attributes.object_group = Some(object_group);
        }
        Attribute::ContactInformation(contact_information) => {
            trace!(
                "ModifyAttribute: Contact Information: {}",
                contact_information
            );
            attributes.contact_information = Some(contact_information);
        }
        Attribute::ObjectType(object_type) => {
            trace!("ModifyAttribute: Object Type: {}", object_type);
            attributes.object_type = Some(object_type);
        }
        Attribute::Name(name) => {
            trace!("ModifyAttribute: Name: {}", name);
            // ModifyAttribute replaces an existing single-valued attribute.
            // For Name (multi-valued), we replace the first entry if one exists,
            // otherwise we add the new name (KMIP 1.x index-0 semantics).
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
        Attribute::UniqueIdentifier(unique_identifier) => {
            trace!("ModifyAttribute: Unique Identifier: {}", unique_identifier);
            attributes.unique_identifier = Some(unique_identifier);
        }
        Attribute::X509CertificateSubject(x509_certificate_subject) => {
            trace!(
                "ModifyAttribute: X509 Certificate Subject: {}",
                x509_certificate_subject
            );
            attributes.x_509_certificate_subject = Some(x509_certificate_subject);
        }
        Attribute::X509CertificateIssuer(x509_certificate_issuer) => {
            trace!(
                "ModifyAttribute: X509 Certificate Issuer: {}",
                x509_certificate_issuer
            );
            attributes.x_509_certificate_issuer = Some(x509_certificate_issuer);
        }
        Attribute::AlternativeName(alternative_name) => {
            trace!("ModifyAttribute: Alternative Name: {}", alternative_name);
            attributes.alternative_name = Some(alternative_name);
        }
        Attribute::AlwaysSensitive(always_sensitive) => {
            trace!("ModifyAttribute: Always Sensitive: {}", always_sensitive);
            attributes.always_sensitive = Some(always_sensitive);
        }
        Attribute::ApplicationSpecificInformation(application_specific_information) => {
            trace!(
                "ModifyAttribute: Application Specific Information: {}",
                application_specific_information
            );
            attributes.application_specific_information = Some(application_specific_information);
        }
        Attribute::ArchiveDate(archive_date) => {
            trace!("ModifyAttribute: Archive Date: {:?}", archive_date);
            attributes.archive_date = Some(archive_date);
        }
        Attribute::AttributeIndex(attribute_index) => {
            trace!("ModifyAttribute: Attribute Index: {:?}", attribute_index);
            attributes.attribute_index = Some(attribute_index);
        }
        Attribute::CertificateAttributes(certificate_attributes) => {
            trace!(
                "ModifyAttribute: Certificate Attributes: {}",
                certificate_attributes
            );
            attributes.certificate_attributes = Some(certificate_attributes);
        }
        Attribute::CertificateType(certificate_type) => {
            trace!("ModifyAttribute: Certificate Type: {}", certificate_type);
            attributes.certificate_type = Some(certificate_type);
        }
        Attribute::CertificateLength(certificate_length) => {
            trace!(
                "ModifyAttribute: Certificate Length: {}",
                certificate_length
            );
            attributes.certificate_length = Some(certificate_length);
        }
        Attribute::Comment(comment) => {
            trace!("ModifyAttribute: Comment: {}", comment);
            attributes.comment = Some(comment);
        }
        Attribute::CompromiseDate(compromise_date) => {
            trace!("ModifyAttribute: Compromise Date: {}", compromise_date);
            attributes.compromise_date = Some(compromise_date);
        }
        Attribute::CompromiseOccurrenceDate(compromise_occurrence_date) => {
            trace!(
                "ModifyAttribute: Compromise Occurrence Date: {}",
                compromise_occurrence_date
            );
            attributes.compromise_occurrence_date = Some(compromise_occurrence_date);
        }
        Attribute::Critical(critical) => {
            trace!("ModifyAttribute: Critical: {}", critical);
            attributes.critical = Some(critical);
        }
        Attribute::Description(description) => {
            trace!("ModifyAttribute: Description: {}", description);
            attributes.description = Some(description);
        }
        Attribute::DestroyDate(destroy_date) => {
            trace!("ModifyAttribute: Destroy Date: {}", destroy_date);
            attributes.destroy_date = Some(destroy_date);
        }
        Attribute::DigitalSignatureAlgorithm(digital_signature_algorithm) => {
            trace!(
                "ModifyAttribute: Digital Signature Algorithm: {}",
                digital_signature_algorithm
            );
            attributes.digital_signature_algorithm = Some(digital_signature_algorithm);
        }
        Attribute::Extractable(extractable) => {
            trace!("ModifyAttribute: Extractable: {}", extractable);
            attributes.extractable = Some(extractable);
        }
        Attribute::Fresh(fresh) => {
            trace!("ModifyAttribute: Fresh: {}", fresh);
            attributes.fresh = Some(fresh);
        }
        Attribute::InitialDate(initial_date) => {
            trace!("ModifyAttribute: Initial Date: {}", initial_date);
            attributes.initial_date = Some(initial_date);
        }
        Attribute::KeyFormatType(key_format_type) => {
            trace!("ModifyAttribute: Key Format Type: {}", key_format_type);
            attributes.key_format_type = Some(key_format_type);
        }
        Attribute::KeyValueLocation(key_value_location) => {
            trace!(
                "ModifyAttribute: Key Value Location: {}",
                key_value_location
            );
            attributes.key_value_location = Some(key_value_location);
        }
        Attribute::KeyValuePresent(key_value_present) => {
            trace!("ModifyAttribute: Key Value Present: {}", key_value_present);
            attributes.key_value_present = Some(key_value_present);
        }
        Attribute::LastChangeDate(last_change_date) => {
            trace!("ModifyAttribute: Last Change Date: {}", last_change_date);
            attributes.last_change_date = Some(last_change_date);
        }
        Attribute::LeaseTime(lease_time) => {
            trace!("ModifyAttribute: Lease Time: {}", lease_time);
            attributes.lease_time = Some(lease_time);
        }
        Attribute::NeverExtractable(never_extractable) => {
            trace!("ModifyAttribute: Never Extractable: {}", never_extractable);
            attributes.never_extractable = Some(never_extractable);
        }
        Attribute::NistKeyType(nist_key_type) => {
            trace!("ModifyAttribute: Nist Key Type: {}", nist_key_type);
            attributes.nist_key_type = Some(nist_key_type);
        }
        Attribute::ObjectGroupMember(object_group_member) => {
            trace!(
                "ModifyAttribute: Object Group Member: {}",
                object_group_member
            );
            attributes.object_group_member = Some(object_group_member);
        }
        Attribute::OpaqueDataType(opaque_data_type) => {
            trace!("ModifyAttribute: Opaque Data Type: {}", opaque_data_type);
            attributes.opaque_data_type = Some(opaque_data_type);
        }
        Attribute::OriginalCreationDate(original_creation_date) => {
            trace!(
                "ModifyAttribute: Original Creation Date: {}",
                original_creation_date
            );
            attributes.original_creation_date = Some(original_creation_date);
        }
        Attribute::Pkcs12FriendlyName(pkcs12_friendly_name) => {
            trace!(
                "ModifyAttribute: PKCS12 Friendly Name: {}",
                pkcs12_friendly_name
            );
            attributes.pkcs_12_friendly_name = Some(pkcs12_friendly_name);
        }
        Attribute::ProcessStartDate(process_start_date) => {
            trace!(
                "ModifyAttribute: Process Start Date: {}",
                process_start_date
            );
            attributes.process_start_date = Some(process_start_date);
        }
        Attribute::ProtectStopDate(protect_stop_date) => {
            trace!("ModifyAttribute: Protect Stop Date: {}", protect_stop_date);
            attributes.protect_stop_date = Some(protect_stop_date);
        }
        Attribute::ProtectionLevel(protection_level) => {
            trace!("ModifyAttribute: Protection Level: {}", protection_level);
            attributes.protection_level = Some(protection_level);
        }
        Attribute::ProtectionPeriod(protection_period) => {
            trace!("ModifyAttribute: Protection Period: {}", protection_period);
            attributes.protection_period = Some(protection_period);
        }
        Attribute::ProtectionStorageMasks(protection_storage_masks) => {
            trace!(
                "ModifyAttribute: Protection Storage Masks: {}",
                protection_storage_masks
            );
            attributes.protection_storage_masks = Some(protection_storage_masks);
        }
        Attribute::QuantumSafe(quantum_safe) => {
            trace!("ModifyAttribute: Quantum Safe: {}", quantum_safe);
            attributes.quantum_safe = Some(quantum_safe);
        }
        Attribute::RandomNumberGenerator(random_number_generator) => {
            trace!(
                "ModifyAttribute: Random Number Generator: {}",
                random_number_generator
            );
            attributes.random_number_generator = Some(random_number_generator);
        }
        Attribute::RevocationReason(revocation_reason) => {
            trace!("ModifyAttribute: Revocation Reason: {}", revocation_reason);
            attributes.revocation_reason = Some(revocation_reason);
        }
        Attribute::RotateDate(rotate_date) => {
            trace!("ModifyAttribute: Rotate Date: {}", rotate_date);
            attributes.rotate_date = Some(rotate_date);
        }
        Attribute::RotateGeneration(rotate_generation) => {
            trace!("ModifyAttribute: Rotate Generation: {}", rotate_generation);
            attributes.rotate_generation = Some(rotate_generation);
        }
        Attribute::RotateInterval(rotate_interval) => {
            trace!("ModifyAttribute: Rotate Interval: {}", rotate_interval);
            attributes.rotate_interval = Some(rotate_interval);
        }
        Attribute::RotateLatest(rotate_latest) => {
            trace!("ModifyAttribute: Rotate Latest: {}", rotate_latest);
            attributes.rotate_latest = Some(rotate_latest);
        }
        Attribute::RotateName(rotate_name) => {
            trace!("ModifyAttribute: Rotate Name: {}", rotate_name);
            attributes.rotate_name = Some(rotate_name);
        }
        Attribute::RotateOffset(rotate_offset) => {
            trace!("ModifyAttribute: Rotate Offset: {}", rotate_offset);
            attributes.rotate_offset = Some(rotate_offset);
        }
        Attribute::Sensitive(sensitive) => {
            trace!("ModifyAttribute: Sensitive: {}", sensitive);
            attributes.sensitive = Some(sensitive);
        }
        Attribute::ShortUniqueIdentifier(short_unique_identifier) => {
            trace!(
                "ModifyAttribute: Short Unique Identifier: {}",
                short_unique_identifier
            );
            attributes.short_unique_identifier = Some(short_unique_identifier);
        }
        Attribute::State(_state) => {
            // Already caught by the read-only guard above; unreachable, but be explicit.
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "ModifyAttribute: State is read-only".to_owned(),
            ));
        }
        Attribute::UsageLimits(usage_limits) => {
            trace!("ModifyAttribute: Usage Limits: {}", usage_limits);
            attributes.usage_limits = Some(usage_limits);
        }
        Attribute::X509CertificateIdentifier(x509_certificate_identifier) => {
            trace!(
                "ModifyAttribute: X509 Certificate Identifier: {}",
                x509_certificate_identifier
            );
            attributes.x_509_certificate_identifier = Some(x509_certificate_identifier);
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
