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
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;
    trace!("Set Attribute: Retrieved target object");

    let mut attributes = owm.attributes_mut().clone();

    // Check if the attribute is allowed to be set
    match request.new_attribute {
        Attribute::ActivationDate(activation_date) => {
            trace!("Set Attribute: Activation Date: {}", activation_date);
            attributes.activation_date = Some(activation_date);
        }
        Attribute::CryptographicAlgorithm(cryptographic_algorithm) => {
            trace!(
                "Set Attribute: Cryptographic Algorithm: {}",
                cryptographic_algorithm
            );
            attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
        }
        Attribute::CryptographicLength(length) => {
            trace!("Set Attribute: Cryptographic Length: {}", length);
            attributes.cryptographic_length = Some(length);
        }
        Attribute::CryptographicParameters(parameters) => {
            trace!("Set Attribute: Cryptographic Parameters: {}", parameters);
            attributes.cryptographic_parameters = Some(parameters);
        }
        Attribute::CryptographicDomainParameters(domain_parameters) => {
            trace!(
                "Set Attribute: Cryptographic Domain Parameters: {}",
                domain_parameters
            );
            attributes.cryptographic_domain_parameters = Some(domain_parameters);
        }
        Attribute::CryptographicUsageMask(usage_mask) => {
            trace!("Set Attribute: Cryptographic Usage Mask: {}", usage_mask);
            attributes.cryptographic_usage_mask = Some(usage_mask);
        }
        Attribute::Digest(digest) => {
            trace!("Set Attribute: Digest: {}", digest);
            attributes.digest = Some(digest);
        }
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
        Attribute::DeactivationDate(deactivation_date) => {
            trace!("Set Attribute: Deactivation Date: {}", deactivation_date);
            attributes.deactivation_date = Some(deactivation_date);
        }
        Attribute::ObjectGroup(object_group) => {
            trace!("Set Attribute: Object Group: {}", object_group);
            attributes.object_group = Some(object_group);
        }
        Attribute::ContactInformation(contact_information) => {
            trace!(
                "Set Attribute: Contact Information: {}",
                contact_information
            );
            attributes.contact_information = Some(contact_information);
        }
        Attribute::ObjectType(object_type) => {
            trace!("Set Attribute: Object Type: {}", object_type);
            attributes.object_type = Some(object_type);
        }
        Attribute::Name(name) => {
            trace!("Set Attribute: Name: {}", name);
            // if name does not exist in attributes, add it
            // if name exists, replace it
            let names = attributes.name.get_or_insert(vec![]);
            // check if the name already exists
            if !names.iter().any(|n| n == &name) {
                names.push(name);
            }
        }
        Attribute::UniqueIdentifier(unique_identifier) => {
            trace!("Set Attribute: Unique Identifier: {}", unique_identifier);
            attributes.unique_identifier = Some(unique_identifier);
        }
        Attribute::X509CertificateSubject(x509_certificate_subject) => {
            trace!(
                "Set Attribute: X509 Certificate Subject: {}",
                x509_certificate_subject
            );
            attributes.x_509_certificate_subject = Some(x509_certificate_subject);
        }
        Attribute::X509CertificateIssuer(x509_certificate_issuer) => {
            trace!(
                "Set Attribute: X509 Certificate Issuer: {}",
                x509_certificate_issuer
            );
            attributes.x_509_certificate_issuer = Some(x509_certificate_issuer);
        }
        Attribute::AlternativeName(alternative_name) => {
            trace!("Set Attribute: Alternative Name: {}", alternative_name);
            attributes.alternative_name = Some(alternative_name);
        }
        Attribute::AlwaysSensitive(always_sensitive) => {
            trace!("Set Attribute: Always Sensitive: {}", always_sensitive);
            attributes.always_sensitive = Some(always_sensitive);
        }
        Attribute::ApplicationSpecificInformation(application_specific_information) => {
            trace!(
                "Set Attribute: Application Specific Information: {}",
                application_specific_information
            );
            attributes.application_specific_information = Some(application_specific_information);
        }
        Attribute::ArchiveDate(archive_date) => {
            trace!("Set Attribute: Archive Date: {:?}", archive_date);
            attributes.archive_date = Some(archive_date);
        }
        Attribute::AttributeIndex(attribute_index) => {
            trace!("Set Attribute: Attribute Index: {:?}", attribute_index);
            attributes.attribute_index = Some(attribute_index);
        }
        Attribute::CertificateAttributes(certificate_attributes) => {
            trace!(
                "Set Attribute: Certificate Attributes: {}",
                certificate_attributes
            );
            attributes.certificate_attributes = Some(certificate_attributes);
        }
        Attribute::CertificateType(certificate_type) => {
            trace!("Set Attribute: Certificate Type: {}", certificate_type);
            attributes.certificate_type = Some(certificate_type);
        }
        Attribute::CertificateLength(certificate_length) => {
            trace!("Set Attribute: Certificate Length: {}", certificate_length);
            attributes.certificate_length = Some(certificate_length);
        }
        Attribute::Comment(comment) => {
            trace!("Set Attribute: Comment: {}", comment);
            attributes.comment = Some(comment);
        }
        Attribute::CompromiseDate(compromise_date) => {
            trace!("Set Attribute: Compromise Date: {}", compromise_date);
            attributes.compromise_date = Some(compromise_date);
        }
        Attribute::CompromiseOccurrenceDate(compromise_occurrence_date) => {
            trace!(
                "Set Attribute: Compromise Occurrence Date: {}",
                compromise_occurrence_date
            );
            attributes.compromise_occurrence_date = Some(compromise_occurrence_date);
        }
        Attribute::Critical(critical) => {
            trace!("Set Attribute: Critical: {}", critical);
            attributes.critical = Some(critical);
        }
        Attribute::Description(description) => {
            trace!("Set Attribute: Description: {}", description);
            attributes.description = Some(description);
        }
        Attribute::DestroyDate(destroy_date) => {
            trace!("Set Attribute: Destroy Date: {}", destroy_date);
            attributes.destroy_date = Some(destroy_date);
        }
        Attribute::DigitalSignatureAlgorithm(digital_signature_algorithm) => {
            trace!(
                "Set Attribute: Digital Signature Algorithm: {}",
                digital_signature_algorithm
            );
            attributes.digital_signature_algorithm = Some(digital_signature_algorithm);
        }
        Attribute::Extractable(extractable) => {
            trace!("Set Attribute: Extractable: {}", extractable);
            attributes.extractable = Some(extractable);
        }
        Attribute::Fresh(fresh) => {
            trace!("Set Attribute: Fresh: {}", fresh);
            attributes.fresh = Some(fresh);
        }
        Attribute::InitialDate(initial_date) => {
            trace!("Set Attribute: Initial Date: {}", initial_date);
            attributes.initial_date = Some(initial_date);
        }
        Attribute::KeyFormatType(key_format_type) => {
            trace!("Set Attribute: Key Format Type: {}", key_format_type);
            attributes.key_format_type = Some(key_format_type);
        }
        Attribute::KeyValueLocation(key_value_location) => {
            trace!("Set Attribute: Key Value Location: {}", key_value_location);
            attributes.key_value_location = Some(key_value_location);
        }
        Attribute::KeyValuePresent(key_value_present) => {
            trace!("Set Attribute: Key Value Present: {}", key_value_present);
            attributes.key_value_present = Some(key_value_present);
        }
        Attribute::LastChangeDate(last_change_date) => {
            trace!("Set Attribute: Last Change Date: {}", last_change_date);
            attributes.last_change_date = Some(last_change_date);
        }
        Attribute::LeaseTime(lease_time) => {
            trace!("Set Attribute: Lease Time: {}", lease_time);
            attributes.lease_time = Some(lease_time);
        }
        Attribute::NeverExtractable(never_extractable) => {
            trace!("Set Attribute: Never Extractable: {}", never_extractable);
            attributes.never_extractable = Some(never_extractable);
        }
        Attribute::NistKeyType(nist_key_type) => {
            trace!("Set Attribute: Nist Key Type: {}", nist_key_type);
            attributes.nist_key_type = Some(nist_key_type);
        }
        Attribute::ObjectGroupMember(object_group_member) => {
            trace!(
                "Set Attribute: Object Group Member: {}",
                object_group_member
            );
            attributes.object_group_member = Some(object_group_member);
        }
        Attribute::OpaqueDataType(opaque_data_type) => {
            trace!("Set Attribute: Opaque Data Type: {}", opaque_data_type);
            attributes.opaque_data_type = Some(opaque_data_type);
        }
        Attribute::OriginalCreationDate(original_creation_date) => {
            trace!(
                "Set Attribute: Original Creation Date: {}",
                original_creation_date
            );
            attributes.original_creation_date = Some(original_creation_date);
        }
        Attribute::Pkcs12FriendlyName(pkcs12_friendly_name) => {
            trace!(
                "Set Attribute: PKCS12 Friendly Name: {}",
                pkcs12_friendly_name
            );
            attributes.pkcs_12_friendly_name = Some(pkcs12_friendly_name);
        }
        Attribute::ProcessStartDate(process_start_date) => {
            trace!("Set Attribute: Process Start Date: {}", process_start_date);
            attributes.process_start_date = Some(process_start_date);
        }
        Attribute::ProtectStopDate(protect_stop_date) => {
            trace!("Set Attribute: Protect Stop Date: {}", protect_stop_date);
            attributes.protect_stop_date = Some(protect_stop_date);
        }
        Attribute::ProtectionLevel(protection_level) => {
            trace!("Set Attribute: Protection Level: {}", protection_level);
            attributes.protection_level = Some(protection_level);
        }
        Attribute::ProtectionPeriod(protection_period) => {
            trace!("Set Attribute: Protection Period: {}", protection_period);
            attributes.protection_period = Some(protection_period);
        }
        Attribute::ProtectionStorageMasks(protection_storage_masks) => {
            trace!(
                "Set Attribute: Protection Storage Masks: {}",
                protection_storage_masks
            );
            attributes.protection_storage_masks = Some(protection_storage_masks);
        }
        Attribute::QuantumSafe(quantum_safe) => {
            trace!("Set Attribute: Quantum Safe: {}", quantum_safe);
            attributes.quantum_safe = Some(quantum_safe);
        }
        Attribute::RandomNumberGenerator(random_number_generator) => {
            trace!(
                "Set Attribute: Random Number Generator: {}",
                random_number_generator
            );
            attributes.random_number_generator = Some(random_number_generator);
        }
        Attribute::RevocationReason(revocation_reason) => {
            trace!("Set Attribute: Revocation Reason: {}", revocation_reason);
            attributes.revocation_reason = Some(revocation_reason);
        }
        Attribute::RotateDate(rotate_date) => {
            trace!("Set Attribute: Rotate Date: {}", rotate_date);
            attributes.rotate_date = Some(rotate_date);
        }
        Attribute::RotateGeneration(rotate_generation) => {
            trace!("Set Attribute: Rotate Generation: {}", rotate_generation);
            attributes.rotate_generation = Some(rotate_generation);
        }
        Attribute::RotateInterval(rotate_interval) => {
            trace!("Set Attribute: Rotate Interval: {}", rotate_interval);
            attributes.rotate_interval = Some(rotate_interval);
        }
        Attribute::RotateLatest(rotate_latest) => {
            trace!("Set Attribute: Rotate Latest: {}", rotate_latest);
            attributes.rotate_latest = Some(rotate_latest);
        }
        Attribute::RotateName(rotate_name) => {
            trace!("Set Attribute: Rotate Name: {}", rotate_name);
            attributes.rotate_name = Some(rotate_name);
        }
        Attribute::RotateOffset(rotate_offset) => {
            trace!("Set Attribute: Rotate Offset: {}", rotate_offset);
            attributes.rotate_offset = Some(rotate_offset);
        }
        Attribute::Sensitive(sensitive) => {
            trace!("Set Attribute: Sensitive: {}", sensitive);
            attributes.sensitive = Some(sensitive);
        }
        Attribute::ShortUniqueIdentifier(short_unique_identifier) => {
            trace!(
                "Set Attribute: Short Unique Identifier: {}",
                short_unique_identifier
            );
            attributes.short_unique_identifier = Some(short_unique_identifier);
        }
        Attribute::State(_state) => {
            return Err(KmsError::InvalidRequest(
                "Set Attribute: State cannot be set. Use Revoke and Destroy to change the object \
                 state"
                    .to_owned(),
            ));
        }
        Attribute::UsageLimits(usage_limits) => {
            trace!("Set Attribute: Usage Limits: {}", usage_limits);
            attributes.usage_limits = Some(usage_limits);
        }
        Attribute::X509CertificateIdentifier(x509_certificate_identifier) => {
            trace!(
                "Set Attribute: X509 Certificate Identifier: {}",
                x509_certificate_identifier
            );
            attributes.x_509_certificate_identifier = Some(x509_certificate_identifier);
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
            let object_attributes = owm.object_mut().attributes_mut()?;
            *object_attributes = attributes.clone();
            debug!("Set Object Attribute: {}", object_attributes);
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
