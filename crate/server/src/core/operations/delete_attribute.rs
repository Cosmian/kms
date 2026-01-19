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
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    let mut attributes = owm.attributes().to_owned();

    if let Some(attribute) = request.current_attribute {
        match attribute {
            Attribute::ActivationDate(activation_date) => {
                if Some(activation_date) == attributes.activation_date {
                    attributes.activation_date = None;
                }
            }
            Attribute::AlternativeName(alternative_name) => {
                if Some(alternative_name) == attributes.alternative_name {
                    attributes.alternative_name = None;
                }
            }
            Attribute::AlwaysSensitive(always_sensitive) => {
                if Some(always_sensitive) == attributes.always_sensitive {
                    attributes.always_sensitive = None;
                }
            }
            Attribute::ApplicationSpecificInformation(application_specific_information) => {
                if Some(application_specific_information)
                    == attributes.application_specific_information
                {
                    attributes.application_specific_information = None;
                }
            }
            Attribute::ArchiveDate(archive_date) => {
                if Some(archive_date) == attributes.archive_date {
                    attributes.archive_date = None;
                }
            }
            Attribute::AttributeIndex(attribute_index) => {
                if Some(attribute_index) == attributes.attribute_index {
                    attributes.attribute_index = None;
                }
            }
            Attribute::CertificateAttributes(certificate_attributes) => {
                if Some(certificate_attributes) == attributes.certificate_attributes {
                    attributes.certificate_attributes = None;
                }
            }
            Attribute::CertificateLength(certificate_length) => {
                if Some(certificate_length) == attributes.certificate_length {
                    attributes.certificate_length = None;
                }
            }
            Attribute::CertificateType(certificate_type) => {
                if Some(certificate_type) == attributes.certificate_type {
                    attributes.certificate_type = None;
                }
            }
            Attribute::Comment(comment) => {
                if Some(comment) == attributes.comment {
                    attributes.comment = None;
                }
            }
            Attribute::CompromiseDate(compromise_date) => {
                if Some(compromise_date) == attributes.compromise_date {
                    attributes.compromise_date = None;
                }
            }
            Attribute::CompromiseOccurrenceDate(compromise_occurrence_date) => {
                if Some(compromise_occurrence_date) == attributes.compromise_occurrence_date {
                    attributes.compromise_occurrence_date = None;
                }
            }
            Attribute::ContactInformation(contact_information) => {
                if Some(contact_information) == attributes.contact_information {
                    attributes.contact_information = None;
                }
            }
            Attribute::Critical(critical) => {
                if Some(critical) == attributes.critical {
                    attributes.critical = None;
                }
            }
            Attribute::CryptographicAlgorithm(algo) => {
                if Some(algo) == attributes.cryptographic_algorithm {
                    attributes.cryptographic_algorithm = None;
                }
            }
            Attribute::CryptographicDomainParameters(domain_parameters) => {
                if Some(domain_parameters) == attributes.cryptographic_domain_parameters {
                    attributes.cryptographic_domain_parameters = None;
                }
            }
            Attribute::CryptographicLength(length) => {
                if Some(length) == attributes.cryptographic_length {
                    attributes.cryptographic_length = None;
                    // Directly modify underlying object key_block where applicable
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
            Attribute::CryptographicParameters(parameters) => {
                if Some(parameters) == attributes.cryptographic_parameters {
                    attributes.cryptographic_parameters = None;
                }
            }
            Attribute::CryptographicUsageMask(usage_mask) => {
                if Some(usage_mask) == attributes.cryptographic_usage_mask {
                    attributes.cryptographic_usage_mask = None;
                }
            }
            Attribute::DeactivationDate(deactivation_date) => {
                if Some(deactivation_date) == attributes.deactivation_date {
                    attributes.deactivation_date = None;
                }
            }
            Attribute::Description(description) => {
                if Some(description) == attributes.description {
                    attributes.description = None;
                }
            }
            Attribute::DestroyDate(destroy_date) => {
                if Some(destroy_date) == attributes.destroy_date {
                    attributes.destroy_date = None;
                }
            }
            Attribute::Digest(digest) => {
                if Some(digest) == attributes.digest {
                    attributes.digest = None;
                }
            }
            Attribute::DigitalSignatureAlgorithm(digital_signature_algorithm) => {
                if Some(digital_signature_algorithm) == attributes.digital_signature_algorithm {
                    attributes.digital_signature_algorithm = None;
                }
            }
            Attribute::Extractable(extractable) => {
                if Some(extractable) == attributes.extractable {
                    attributes.extractable = None;
                }
            }
            Attribute::Fresh(fresh) => {
                if Some(fresh) == attributes.fresh {
                    attributes.fresh = None;
                }
            }
            Attribute::InitialDate(initial_date) => {
                if Some(initial_date) == attributes.initial_date {
                    attributes.initial_date = None;
                }
            }
            Attribute::KeyFormatType(key_format_type) => {
                if Some(key_format_type) == attributes.key_format_type {
                    attributes.key_format_type = None;
                }
            }
            Attribute::KeyValueLocation(key_value_location_type) => {
                if Some(key_value_location_type) == attributes.key_value_location {
                    attributes.key_value_location = None;
                }
            }
            Attribute::KeyValuePresent(key_value_present) => {
                if Some(key_value_present) == attributes.key_value_present {
                    attributes.key_value_present = None;
                }
            }
            Attribute::LastChangeDate(last_change_date) => {
                if Some(last_change_date) == attributes.last_change_date {
                    attributes.last_change_date = None;
                }
            }
            Attribute::LeaseTime(lease_time) => {
                if Some(lease_time) == attributes.lease_time {
                    attributes.lease_time = None;
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
            Attribute::NeverExtractable(never_extractable) => {
                if Some(never_extractable) == attributes.never_extractable {
                    attributes.never_extractable = None;
                }
            }
            Attribute::NistKeyType(nist_key_type) => {
                if Some(nist_key_type) == attributes.nist_key_type {
                    attributes.nist_key_type = None;
                }
            }
            Attribute::ObjectGroup(object_group) => {
                if Some(object_group) == attributes.object_group {
                    attributes.object_group = None;
                }
            }
            Attribute::ObjectGroupMember(object_group_member) => {
                if Some(object_group_member) == attributes.object_group_member {
                    attributes.object_group_member = None;
                }
            }
            Attribute::ObjectType(object_type) => {
                if Some(object_type) == attributes.object_type {
                    attributes.object_type = None;
                }
            }
            Attribute::OpaqueDataType(opaque_data_type) => {
                if Some(opaque_data_type) == attributes.opaque_data_type {
                    attributes.opaque_data_type = None;
                }
            }
            Attribute::OriginalCreationDate(original_creation_date) => {
                if Some(original_creation_date) == attributes.original_creation_date {
                    attributes.original_creation_date = None;
                }
            }
            Attribute::Pkcs12FriendlyName(pkcs12_friendly_name) => {
                if Some(pkcs12_friendly_name) == attributes.pkcs_12_friendly_name {
                    attributes.pkcs_12_friendly_name = None;
                }
            }
            Attribute::ProcessStartDate(process_start_date) => {
                if Some(process_start_date) == attributes.process_start_date {
                    attributes.process_start_date = None;
                }
            }
            Attribute::ProtectStopDate(protect_stop_date) => {
                if Some(protect_stop_date) == attributes.protect_stop_date {
                    attributes.protect_stop_date = None;
                }
            }
            Attribute::ProtectionLevel(protection_level) => {
                if Some(protection_level) == attributes.protection_level {
                    attributes.protection_level = None;
                }
            }
            Attribute::ProtectionPeriod(protection_period) => {
                if Some(protection_period) == attributes.protection_period {
                    attributes.protection_period = None;
                }
            }
            Attribute::ProtectionStorageMasks(protection_storage_masks) => {
                if Some(protection_storage_masks) == attributes.protection_storage_masks {
                    attributes.protection_storage_masks = None;
                }
            }
            Attribute::QuantumSafe(quantum_safe) => {
                if Some(quantum_safe) == attributes.quantum_safe {
                    attributes.quantum_safe = None;
                }
            }
            Attribute::RandomNumberGenerator(random_number_generator) => {
                if Some(random_number_generator) == attributes.random_number_generator {
                    attributes.random_number_generator = None;
                }
            }
            Attribute::RevocationReason(revocation_reason) => {
                if Some(revocation_reason) == attributes.revocation_reason {
                    attributes.revocation_reason = None;
                }
            }
            Attribute::RotateDate(rotate_date) => {
                if Some(rotate_date) == attributes.rotate_date {
                    attributes.rotate_date = None;
                }
            }
            Attribute::RotateGeneration(rotate_generation) => {
                if Some(rotate_generation) == attributes.rotate_generation {
                    attributes.rotate_generation = None;
                }
            }
            Attribute::RotateInterval(rotate_interval) => {
                if Some(rotate_interval) == attributes.rotate_interval {
                    attributes.rotate_interval = None;
                }
            }
            Attribute::RotateLatest(rotate_latest) => {
                if Some(rotate_latest) == attributes.rotate_latest {
                    attributes.rotate_latest = None;
                }
            }
            Attribute::RotateName(rotate_name) => {
                if Some(rotate_name) == attributes.rotate_name {
                    attributes.rotate_name = None;
                }
            }
            Attribute::RotateOffset(rotate_offset) => {
                if Some(rotate_offset) == attributes.rotate_offset {
                    attributes.rotate_offset = None;
                }
            }
            Attribute::Sensitive(sensitive) => {
                if Some(sensitive) == attributes.sensitive {
                    attributes.sensitive = None;
                }
            }
            Attribute::ShortUniqueIdentifier(short_unique_identifier) => {
                if Some(short_unique_identifier) == attributes.short_unique_identifier {
                    attributes.short_unique_identifier = None;
                }
            }
            Attribute::State(state) => {
                if Some(state) == attributes.state {
                    attributes.state = None;
                }
            }
            Attribute::UniqueIdentifier(unique_identifier) => {
                if Some(unique_identifier) == attributes.unique_identifier {
                    attributes.unique_identifier = None;
                }
            }
            Attribute::UsageLimits(usage_limits) => {
                if Some(usage_limits) == attributes.usage_limits {
                    attributes.usage_limits = None;
                }
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                attributes.remove_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                );
            }
            Attribute::X509CertificateIdentifier(x509_certificate_identifier) => {
                if Some(x509_certificate_identifier) == attributes.x_509_certificate_identifier {
                    attributes.x_509_certificate_identifier = None;
                }
            }
            Attribute::X509CertificateIssuer(x509_certificate_issuer) => {
                if Some(x509_certificate_issuer) == attributes.x_509_certificate_issuer {
                    attributes.x_509_certificate_issuer = None;
                }
            }
            Attribute::X509CertificateSubject(x509_certificate_subject) => {
                if Some(x509_certificate_subject) == attributes.x_509_certificate_subject {
                    attributes.x_509_certificate_subject = None;
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
