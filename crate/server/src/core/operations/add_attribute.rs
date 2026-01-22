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

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes_mut().clone();

    // Check if the attribute is allowed to be set
    match request.new_attribute {
        Attribute::ActivationDate(activation_date) => {
            trace!("Activation Date: {:?}", activation_date);
            if attributes.activation_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Activation Date already exists".to_owned(),
                ));
            }
            attributes.activation_date = Some(activation_date);
        }
        Attribute::CryptographicAlgorithm(cryptographic_algorithm) => {
            trace!("Cryptographic Algorithm: {}", cryptographic_algorithm);
            if attributes.cryptographic_algorithm.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Cryptographic Algorithm already exists".to_owned(),
                ));
            }
            attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
        }
        Attribute::CryptographicLength(length) => {
            trace!("Cryptographic Length: {}", length);
            if attributes.cryptographic_length.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Cryptographic Length already exists".to_owned(),
                ));
            }
            attributes.cryptographic_length = Some(length);
        }
        Attribute::CryptographicParameters(parameters) => {
            trace!("Cryptographic Parameters: {}", parameters);
            if attributes.cryptographic_parameters.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Cryptographic Parameters already exists".to_owned(),
                ));
            }
            attributes.cryptographic_parameters = Some(parameters);
        }
        Attribute::CryptographicDomainParameters(domain_parameters) => {
            trace!("Cryptographic Domain Parameters: {}", domain_parameters);
            if attributes.cryptographic_domain_parameters.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Cryptographic Domain Parameters already exists".to_owned(),
                ));
            }
            attributes.cryptographic_domain_parameters = Some(domain_parameters);
        }
        Attribute::CryptographicUsageMask(usage_mask) => {
            trace!("Cryptographic Usage Mask: {}", usage_mask);
            if attributes.cryptographic_usage_mask.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Cryptographic Usage Mask already exists".to_owned(),
                ));
            }
            attributes.cryptographic_usage_mask = Some(usage_mask);
        }
        Attribute::Digest(digest) => {
            trace!("Digest: {}", digest);
            if attributes.digest.is_some() {
                return Err(KmsError::InvalidRequest("Digest already exists".to_owned()));
            }
            attributes.digest = Some(digest);
        }
        Attribute::Link(link) => {
            trace!("Link: {}", link);
            // Link is special case, it can be updated
            if attributes.get_link(link.link_type).is_some() {
                return Err(KmsError::InvalidRequest("Link already exists".to_owned()));
            }
            attributes.set_link(link.link_type, link.linked_object_identifier);
        }
        Attribute::VendorAttribute(vendor_attribute) => {
            trace!("Vendor Attribute: {}", vendor_attribute);
            // Vendor attributes can be updated
            if attributes
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
        Attribute::DeactivationDate(deactivation_date) => {
            trace!("Deactivation Date: {}", deactivation_date);
            if attributes.deactivation_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Deactivation Date already exists".to_owned(),
                ));
            }
            attributes.deactivation_date = Some(deactivation_date);
        }
        Attribute::ObjectGroup(object_group) => {
            trace!("Object Group: {}", object_group);
            if attributes.object_group.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Object Group already exists".to_owned(),
                ));
            }
            attributes.object_group = Some(object_group);
        }
        Attribute::ContactInformation(contact_information) => {
            trace!("Contact Information: {}", contact_information);
            if attributes.contact_information.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Contact Information already exists".to_owned(),
                ));
            }
            attributes.contact_information = Some(contact_information);
        }
        Attribute::ObjectType(object_type) => {
            trace!("Object Type: {}", object_type);
            if attributes.object_type.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Object Type already exists".to_owned(),
                ));
            }
            attributes.object_type = Some(object_type);
        }
        Attribute::Name(name) => {
            trace!("Name: {name}");
            // Name is special case, can have multiple names
            let names = attributes.name.get_or_insert(vec![]);
            // check if the exact same name already exists
            if names.iter().any(|n| n == &name) {
                // KMIP 2.1 profiles expect NonUniqueNameAttribute (Non_Unique_Name_Attribute)
                // when attempting to add a duplicate Name value. Vector BL-M-8-21 asserts
                // ResultStatus=OperationFailed, ResultReason=NonUniqueNameAttribute, ResultMessage="DENIED".
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Non_Unique_Name_Attribute,
                    "DENIED".to_owned(),
                ));
            }
            names.push(name);
        }
        Attribute::UniqueIdentifier(unique_identifier) => {
            trace!("Unique Identifier: {}", unique_identifier);
            if attributes.unique_identifier.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Unique Identifier already exists".to_owned(),
                ));
            }
            attributes.unique_identifier = Some(unique_identifier);
        }
        Attribute::X509CertificateSubject(x509_certificate_subject) => {
            trace!("X509 Certificate Subject: {}", x509_certificate_subject);
            if attributes.x_509_certificate_subject.is_some() {
                return Err(KmsError::InvalidRequest(
                    "X509 Certificate Subject already exists".to_owned(),
                ));
            }
            attributes.x_509_certificate_subject = Some(x509_certificate_subject);
        }
        Attribute::X509CertificateIssuer(x509_certificate_issuer) => {
            trace!("X509 Certificate Issuer: {:?}", x509_certificate_issuer);
            if attributes.x_509_certificate_issuer.is_some() {
                return Err(KmsError::InvalidRequest(
                    "X509 Certificate Issuer already exists".to_owned(),
                ));
            }
            attributes.x_509_certificate_issuer = Some(x509_certificate_issuer);
        }
        Attribute::AlternativeName(alternative_name) => {
            trace!("Alternative Name: {:?}", alternative_name);
            if attributes.alternative_name.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Alternative Name already exists".to_owned(),
                ));
            }
            attributes.alternative_name = Some(alternative_name);
        }
        Attribute::AlwaysSensitive(always_sensitive) => {
            trace!("Always Sensitive: {:?}", always_sensitive);
            if attributes.always_sensitive.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Always Sensitive already exists".to_owned(),
                ));
            }
            attributes.always_sensitive = Some(always_sensitive);
        }
        Attribute::ApplicationSpecificInformation(application_specific_information) => {
            trace!(
                "Application Specific Information: {:?}",
                application_specific_information
            );
            if attributes.application_specific_information.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Application Specific Information already exists".to_owned(),
                ));
            }
            attributes.application_specific_information = Some(application_specific_information);
        }
        Attribute::ArchiveDate(archive_date) => {
            trace!("Archive Date: {:?}", archive_date);
            if attributes.archive_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Archive Date already exists".to_owned(),
                ));
            }
            attributes.archive_date = Some(archive_date);
        }
        Attribute::AttributeIndex(attribute_index) => {
            trace!("Attribute Index: {:?}", attribute_index);
            if attributes.attribute_index.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Attribute Index already exists".to_owned(),
                ));
            }
            attributes.attribute_index = Some(attribute_index);
        }
        Attribute::CertificateAttributes(certificate_attributes) => {
            trace!("Certificate Attributes: {}", certificate_attributes);
            if attributes.certificate_attributes.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Certificate Attributes already exists".to_owned(),
                ));
            }
            attributes.certificate_attributes = Some(certificate_attributes);
        }
        Attribute::CertificateType(certificate_type) => {
            trace!("Certificate Type: {:?}", certificate_type);
            if attributes.certificate_type.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Certificate Type already exists".to_owned(),
                ));
            }
            attributes.certificate_type = Some(certificate_type);
        }
        Attribute::CertificateLength(certificate_length) => {
            trace!("Certificate Length: {:?}", certificate_length);
            if attributes.certificate_length.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Certificate Length already exists".to_owned(),
                ));
            }
            attributes.certificate_length = Some(certificate_length);
        }
        Attribute::Comment(comment) => {
            trace!("Comment: {:?}", comment);
            if attributes.comment.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Comment already exists".to_owned(),
                ));
            }
            attributes.comment = Some(comment);
        }
        Attribute::CompromiseDate(compromise_date) => {
            trace!("Compromise Date: {:?}", compromise_date);
            if attributes.compromise_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Compromise Date already exists".to_owned(),
                ));
            }
            attributes.compromise_date = Some(compromise_date);
        }
        Attribute::CompromiseOccurrenceDate(compromise_occurrence_date) => {
            trace!(
                "Add Attribute: Compromise Occurrence Date: {:?}",
                compromise_occurrence_date
            );
            if attributes.compromise_occurrence_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Compromise Occurrence Date already exists".to_owned(),
                ));
            }
            attributes.compromise_occurrence_date = Some(compromise_occurrence_date);
        }
        Attribute::Critical(critical) => {
            trace!("Critical: {:?}", critical);
            if attributes.critical.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Critical already exists".to_owned(),
                ));
            }
            attributes.critical = Some(critical);
        }
        Attribute::Description(description) => {
            trace!("Description: {:?}", description);
            if attributes.description.is_some() {
                // KMIP expects Attribute_Single_Valued for a duplicate add attempt on a
                // single-valued attribute like Description, with the canonical message "DENIED".
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Attribute_Single_Valued,
                    "DENIED".to_owned(),
                ));
            }
            attributes.description = Some(description);
        }
        Attribute::DestroyDate(destroy_date) => {
            trace!("Destroy Date: {:?}", destroy_date);
            if attributes.destroy_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Destroy Date already exists".to_owned(),
                ));
            }
            attributes.destroy_date = Some(destroy_date);
        }
        Attribute::DigitalSignatureAlgorithm(digital_signature_algorithm) => {
            trace!(
                "Digital Signature Algorithm: {:?}",
                digital_signature_algorithm
            );
            if attributes.digital_signature_algorithm.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Digital Signature Algorithm already exists".to_owned(),
                ));
            }
            attributes.digital_signature_algorithm = Some(digital_signature_algorithm);
        }
        Attribute::Extractable(extractable) => {
            trace!("Extractable: {:?}", extractable);
            if attributes.extractable.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Extractable already exists".to_owned(),
                ));
            }
            attributes.extractable = Some(extractable);
        }
        Attribute::Fresh(fresh) => {
            trace!("Fresh: {:?}", fresh);
            if attributes.fresh.is_some() {
                return Err(KmsError::InvalidRequest("Fresh already exists".to_owned()));
            }
            attributes.fresh = Some(fresh);
        }
        Attribute::InitialDate(initial_date) => {
            trace!("Initial Date: {:?}", initial_date);
            if attributes.initial_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Initial Date already exists".to_owned(),
                ));
            }
            attributes.initial_date = Some(initial_date);
        }
        Attribute::KeyFormatType(key_format_type) => {
            trace!("Key Format Type: {:?}", key_format_type);
            if attributes.key_format_type.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Key Format Type already exists".to_owned(),
                ));
            }
            attributes.key_format_type = Some(key_format_type);
        }
        Attribute::KeyValueLocation(key_value_location_type) => {
            trace!("Key Value Location: {:?}", key_value_location_type);
            if attributes.key_value_location.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Key Value Location already exists".to_owned(),
                ));
            }
            attributes.key_value_location = Some(key_value_location_type);
        }
        Attribute::KeyValuePresent(key_value_present) => {
            trace!("Key Value Present: {:?}", key_value_present);
            if attributes.key_value_present.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Key Value Present already exists".to_owned(),
                ));
            }
            attributes.key_value_present = Some(key_value_present);
        }
        Attribute::LastChangeDate(last_change_date) => {
            trace!("Last Change Date: {:?}", last_change_date);
            if attributes.last_change_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Last Change Date already exists".to_owned(),
                ));
            }
            attributes.last_change_date = Some(last_change_date);
        }
        Attribute::LeaseTime(lease_time) => {
            trace!("Lease Time: {:?}", lease_time);
            if attributes.lease_time.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Lease Time already exists".to_owned(),
                ));
            }
            attributes.lease_time = Some(lease_time);
        }
        Attribute::NeverExtractable(never_extractable) => {
            trace!("Never Extractable: {:?}", never_extractable);
            if attributes.never_extractable.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Never Extractable already exists".to_owned(),
                ));
            }
            attributes.never_extractable = Some(never_extractable);
        }
        Attribute::NistKeyType(nist_key_type) => {
            trace!("NIST Key Type: {:?}", nist_key_type);
            if attributes.nist_key_type.is_some() {
                return Err(KmsError::InvalidRequest(
                    "NIST Key Type already exists".to_owned(),
                ));
            }
            attributes.nist_key_type = Some(nist_key_type);
        }
        Attribute::ObjectGroupMember(object_group_member) => {
            trace!("Object Group Member: {:?}", object_group_member);
            if attributes.object_group_member.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Object Group Member already exists".to_owned(),
                ));
            }
            attributes.object_group_member = Some(object_group_member);
        }
        Attribute::OpaqueDataType(opaque_data_type) => {
            trace!("Add Attribute: Opaque Data Type: {:?}", opaque_data_type);
            if attributes.opaque_data_type.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Opaque Data Type already exists".to_owned(),
                ));
            }
            attributes.opaque_data_type = Some(opaque_data_type);
        }
        Attribute::OriginalCreationDate(original_creation_date) => {
            trace!("Original Creation Date: {:?}", original_creation_date);
            if attributes.original_creation_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Original Creation Date already exists".to_owned(),
                ));
            }
            attributes.original_creation_date = Some(original_creation_date);
        }
        Attribute::Pkcs12FriendlyName(pkcs12_friendly_name) => {
            trace!("PKCS12 Friendly Name: {:?}", pkcs12_friendly_name);
            if attributes.pkcs_12_friendly_name.is_some() {
                return Err(KmsError::InvalidRequest(
                    "PKCS12 Friendly Name already exists".to_owned(),
                ));
            }
            attributes.pkcs_12_friendly_name = Some(pkcs12_friendly_name);
        }
        Attribute::ProcessStartDate(process_start_date) => {
            trace!("Process Start Date: {:?}", process_start_date);
            if attributes.process_start_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Process Start Date already exists".to_owned(),
                ));
            }
            attributes.process_start_date = Some(process_start_date);
        }
        Attribute::ProtectStopDate(protect_stop_date) => {
            trace!("Protect Stop Date: {:?}", protect_stop_date);
            if attributes.protect_stop_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Protect Stop Date already exists".to_owned(),
                ));
            }
            attributes.protect_stop_date = Some(protect_stop_date);
        }
        Attribute::ProtectionLevel(protection_level) => {
            trace!("Protection Level: {:?}", protection_level);
            if attributes.protection_level.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Protection Level already exists".to_owned(),
                ));
            }
            attributes.protection_level = Some(protection_level);
        }
        Attribute::ProtectionPeriod(protection_period) => {
            trace!("Protection Period: {:?}", protection_period);
            if attributes.protection_period.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Protection Period already exists".to_owned(),
                ));
            }
            attributes.protection_period = Some(protection_period);
        }
        Attribute::ProtectionStorageMasks(protection_storage_masks) => {
            trace!("Protection Storage Masks: {:?}", protection_storage_masks);
            if attributes.protection_storage_masks.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Protection Storage Masks already exists".to_owned(),
                ));
            }
            attributes.protection_storage_masks = Some(protection_storage_masks);
        }
        Attribute::QuantumSafe(quantum_safe) => {
            trace!("Quantum Safe: {:?}", quantum_safe);
            if attributes.quantum_safe.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Quantum Safe already exists".to_owned(),
                ));
            }
            attributes.quantum_safe = Some(quantum_safe);
        }
        Attribute::RandomNumberGenerator(random_number_generator) => {
            trace!("Random Number Generator: {:?}", random_number_generator);
            if attributes.random_number_generator.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Random Number Generator already exists".to_owned(),
                ));
            }
            attributes.random_number_generator = Some(random_number_generator);
        }
        Attribute::RevocationReason(revocation_reason) => {
            trace!("Revocation Reason: {:?}", revocation_reason);
            if attributes.revocation_reason.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Revocation Reason already exists".to_owned(),
                ));
            }
            attributes.revocation_reason = Some(revocation_reason);
        }
        Attribute::RotateDate(rotate_date) => {
            trace!("Rotate Date: {:?}", rotate_date);
            if attributes.rotate_date.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Date already exists".to_owned(),
                ));
            }
            attributes.rotate_date = Some(rotate_date);
        }
        Attribute::RotateGeneration(rotate_generation) => {
            trace!("Rotate Generation: {:?}", rotate_generation);
            if attributes.rotate_generation.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Generation already exists".to_owned(),
                ));
            }
            attributes.rotate_generation = Some(rotate_generation);
        }
        Attribute::RotateInterval(rotate_interval) => {
            trace!("Rotate Interval: {:?}", rotate_interval);
            if attributes.rotate_interval.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Interval already exists".to_owned(),
                ));
            }
            attributes.rotate_interval = Some(rotate_interval);
        }
        Attribute::RotateLatest(rotate_latest) => {
            trace!("Rotate Latest: {:?}", rotate_latest);
            if attributes.rotate_latest.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Latest already exists".to_owned(),
                ));
            }
            attributes.rotate_latest = Some(rotate_latest);
        }
        Attribute::RotateName(rotate_name) => {
            trace!("Rotate Name: {:?}", rotate_name);
            if attributes.rotate_name.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Name already exists".to_owned(),
                ));
            }
            attributes.rotate_name = Some(rotate_name);
        }
        Attribute::RotateOffset(rotate_offset) => {
            trace!("Rotate Offset: {:?}", rotate_offset);
            if attributes.rotate_offset.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Rotate Offset already exists".to_owned(),
                ));
            }
            attributes.rotate_offset = Some(rotate_offset);
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
        Attribute::ShortUniqueIdentifier(short_unique_identifier) => {
            trace!("Short Unique Identifier: {:?}", short_unique_identifier);
            if attributes.short_unique_identifier.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Short Unique Identifier already exists".to_owned(),
                ));
            }
            attributes.short_unique_identifier = Some(short_unique_identifier);
        }
        Attribute::State(_state) => {
            return Err(KmsError::InvalidRequest(
                "Attribute: State cannot be modified. Use Revoke and Destroy to change the object \
                 state"
                    .to_owned(),
            ));
        }
        Attribute::UsageLimits(usage_limits) => {
            trace!("Usage Limits: {:?}", usage_limits);
            if attributes.usage_limits.is_some() {
                return Err(KmsError::InvalidRequest(
                    "Usage Limits already exists".to_owned(),
                ));
            }
            attributes.usage_limits = Some(usage_limits);
        }
        Attribute::X509CertificateIdentifier(x509_certificate_identifier) => {
            trace!(
                "X509 Certificate Identifier: {:?}",
                x509_certificate_identifier
            );
            if attributes.x_509_certificate_identifier.is_some() {
                return Err(KmsError::InvalidRequest(
                    "X509 Certificate Identifier already exists".to_owned(),
                ));
            }
            attributes.x_509_certificate_identifier = Some(x509_certificate_identifier);
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
