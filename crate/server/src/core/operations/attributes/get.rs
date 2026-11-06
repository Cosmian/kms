use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            KmipOperation,
            extra::tagging::VENDOR_ATTR_TAG,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyMaterial, KeyValue},
            kmip_objects::{
                Object, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey,
            },
            kmip_operations::{GetAttributes, GetAttributesResponse},
            kmip_types::{
                AttributeReference, CryptographicAlgorithm, KeyFormatType, LinkType, Tag,
                UniqueIdentifier, VendorAttribute, VendorAttributeReference,
            },
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, trace};
use openssl::sha;
use strum::IntoEnumIterator;

use crate::{
    core::{
        KMS,
        retrieve_object_utils::retrieve_object_for_operation,
        uid_utils::{ObjectHandle, from_request},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

pub(crate) async fn get_attributes(
    kms: &KMS,
    request: GetAttributes,
    user: &UserId,
) -> KResult<GetAttributesResponse> {
    trace!("GetAttributes request");

    // KMIP 2.1 §6.1.20: an omitted Unique Identifier means the ID Placeholder, which the
    // message layer has already substituted; if it is still absent there is no placeholder.
    let object_handle: ObjectHandle<'_> = from_request(
        Some(
            request
                .unique_identifier
                .as_ref()
                .ok_or(KmsError::UnsupportedPlaceholder)?,
        ),
        "Get Attributes",
    )?;

    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for GetAttributes");
    let req_attributes = request.attribute_reference.unwrap_or_default();
    // KMIP 2.1 §6.1.20: the same Attribute Reference SHALL NOT be repeated.
    for (i, reference) in req_attributes.iter().enumerate() {
        if req_attributes.iter().take(i).any(|r| r == reference) {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "Get Attributes: duplicate Attribute Reference".to_owned(),
            ));
        }
    }
    let attributes = Box::pin(collect_attributes(kms, &owm, req_attributes)).await?;
    trace!("Returning object attributes");
    Ok(GetAttributesResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        attributes,
    })
}

/// The attributes of `owm` named by `req_attributes` (all of them when empty), as Get
/// Attributes reports them: stored values plus the server-derived ones (Digest of a symmetric
/// key, Short Unique Identifier, Sensitive/Extractable defaults, ...). Export returns the same
/// set (KMIP 2.1 §6.1.18: "All of the object's Attributes").
pub(crate) async fn collect_attributes(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    mut req_attributes: Vec<AttributeReference>,
) -> KResult<Attributes> {
    let attributes = match owm.object() {
        Object::Certificate { .. } | Object::OpaqueObject { .. } => {
            // KMIP Attributes retrieved from the dedicated column `Attributes`
            // OpaqueObject has no key block: attributes are only the metadata ones.
            owm.attributes().to_owned()
        }
        Object::PrivateKey(PrivateKey { key_block })
        | Object::PublicKey(PublicKey { key_block })
        | Object::SymmetricKey(SymmetricKey { key_block })
        | Object::PGPKey(PGPKey { key_block, .. })
        | Object::SecretData(SecretData { key_block, .. }) => {
            if let Some(KeyValue::Structure {
                attributes: Some(attributes),
                ..
            }) = key_block.key_value.as_ref()
            {
                let mut attributes = attributes.clone();
                attributes.merge(owm.attributes(), false);
                // Filter out internal vendor tag here as well to avoid leaking into comparisons
                if let Some(vendor_attributes) = attributes.vendor_attributes.as_mut() {
                    vendor_attributes.retain(|va| {
                        !(va.vendor_identification == kms.vendor_id()
                            && va.attribute_name == VENDOR_ATTR_TAG)
                    });
                    if vendor_attributes.is_empty() {
                        attributes.vendor_attributes = None;
                    }
                }
                attributes
            } else {
                let mut a = owm.attributes().to_owned();
                if let Some(vendor_attributes) = a.vendor_attributes.as_mut() {
                    vendor_attributes.retain(|va| {
                        !(va.vendor_identification == kms.vendor_id()
                            && va.attribute_name == VENDOR_ATTR_TAG)
                    });
                    if vendor_attributes.is_empty() {
                        a.vendor_attributes = None;
                    }
                }
                a
            }
        }
        // Defensive overlay: SplitKey crypto metadata (algorithm, length, format type) IS stored
        // in the Attributes table at creation time (see create_split_key.rs). However, as a
        // fallback for imported SplitKey objects or attributes cleared by DeleteAttribute, we
        // read the values from the key_block when the stored Attributes are missing them.
        // This ensures the KMIP contract — Managed Objects SHALL have CryptographicAlgorithm and
        // CryptographicLength as server-set attributes — is always fulfilled.
        Object::SplitKey(SplitKey { key_block, .. }) => {
            let mut a = owm.attributes().to_owned();
            // Overlay key_block crypto metadata if not already in stored attrs.
            if a.cryptographic_algorithm.is_none() {
                a.cryptographic_algorithm = key_block.cryptographic_algorithm;
            }
            if a.cryptographic_length.is_none() {
                a.cryptographic_length = key_block.cryptographic_length;
            }
            if a.key_format_type.is_none() {
                a.key_format_type = Some(key_block.key_format_type);
            }
            // Strip internal tag vendor attribute before returning.
            if let Some(vendor_attributes) = a.vendor_attributes.as_mut() {
                vendor_attributes.retain(|va| {
                    !(va.vendor_identification == kms.vendor_id()
                        && va.attribute_name == VENDOR_ATTR_TAG)
                });
                if vendor_attributes.is_empty() {
                    a.vendor_attributes = None;
                }
            }
            a
        }
        Object::CertificateRequest { .. } => {
            return Err(KmsError::InvalidRequest(format!(
                "get: unsupported object type for {}",
                owm.id()
            )));
        }
    };

    trace!("Retrieved object attributes");
    trace!("Processing requested attribute references");

    // Pre-compute effective cryptographic length for this object when possible.
    // Prefer the attribute if set; otherwise derive from KeyBlock length for symmetric keys.
    // Effective cryptographic length: use attribute if present, otherwise rely ONLY on the
    // KeyBlock's explicit cryptographic_length (do NOT infer from raw bytes). This allows
    // DeleteAttribute to hide the length by clearing both the attribute and the key_block
    // field. Previous behavior inferred from raw key bytes which made deletion impossible
    // to observe.
    let effective_cryptographic_length: Option<i32> =
        attributes
            .cryptographic_length
            .or_else(|| match owm.object() {
                Object::SymmetricKey(SymmetricKey { key_block })
                | Object::PrivateKey(PrivateKey { key_block })
                | Object::PublicKey(PublicKey { key_block })
                | Object::SecretData(SecretData { key_block, .. }) => {
                    key_block.cryptographic_length
                }
                _ => None,
            });

    // Pre-compute effective certificate length for certificate objects when possible.
    let effective_certificate_length: Option<i32> =
        attributes
            .certificate_length
            .or_else(|| match owm.object() {
                Object::Certificate(cert) => i32::try_from(cert.certificate_value.len()).ok(),
                _ => None,
            });

    // request all attributes
    if req_attributes.is_empty() {
        // Standard attributes: include VendorExtension so vendor-defined attributes are returned by default.
        // Exclude only Tag::Tag to avoid injecting server-specific tagging unless explicitly requested.
        req_attributes.extend(
            Tag::iter()
                .filter(|&t| t != Tag::Tag)
                .map(AttributeReference::Standard),
        );
    }

    // request selected attributes
    let mut tags_already_set = false;
    let mut res = Attributes::default();
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification,
                attribute_name,
            }) => {
                // Log what vendor attributes are available on the object before matching
                if let Some(vas) = attributes.vendor_attributes.as_ref() {
                    debug!(
                        "Get Attributes: available vendor attributes: [{}]",
                        vas.iter()
                            .map(|va| format!("{}:{}", va.vendor_identification, va.attribute_name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                } else {
                    debug!("Get Attributes: no vendor attributes present on object");
                }
                if vendor_identification == kms.vendor_id() && attribute_name == VENDOR_ATTR_TAG {
                    if !tags_already_set {
                        let tags = kms.database.retrieve_tags(owm.id()).await?;
                        res.set_tags(kms.vendor_id(), tags)?;
                        tags_already_set = true;
                    }
                } else if let Some(value) =
                    attributes.get_vendor_attribute_value(&vendor_identification, &attribute_name)
                {
                    debug!(
                        "Get Attributes: returning vendor attribute match {}:{}",
                        vendor_identification, attribute_name
                    );
                    res.add_vendor_attribute(VendorAttribute {
                        vendor_identification,
                        attribute_name,
                        attribute_value: value.to_owned(),
                    });
                } else if let Some(value) = owm
                    .attributes()
                    .get_vendor_attribute_value(&vendor_identification, &attribute_name)
                {
                    // Fallback: in case the merged attributes view did not carry the vendor attribute,
                    // return it from the original object attributes.
                    debug!(
                        "Get Attributes: fallback vendor attribute match {}:{} from object attributes",
                        vendor_identification, attribute_name
                    );
                    res.add_vendor_attribute(VendorAttribute {
                        vendor_identification,
                        attribute_name,
                        attribute_value: value.to_owned(),
                    });
                } else {
                    debug!(
                        "Get Attributes: requested vendor attribute not found {}:{}",
                        vendor_identification, attribute_name
                    );
                }
            }
            AttributeReference::Standard(tag) => match tag {
                Tag::ActivationDate => {
                    res.activation_date = attributes.activation_date;
                }
                Tag::Description => {
                    attributes.description.clone_into(&mut res.description);
                }
                Tag::Comment => {
                    attributes.comment.clone_into(&mut res.comment);
                }
                Tag::AlwaysSensitive => {
                    // If AlwaysSensitive is not explicitly set, default to current Sensitive value
                    // and finally default to false when both are absent.
                    res.always_sensitive = attributes
                        .always_sensitive
                        .or(attributes.sensitive)
                        .or(Some(false));
                }
                Tag::ApplicationSpecificInformation => {
                    attributes
                        .application_specific_information
                        .clone_into(&mut res.application_specific_information);
                }
                Tag::ArchiveDate => {
                    res.archive_date = attributes.archive_date;
                }
                Tag::Certificate => {
                    if let Some(certificate_attributes) = attributes.certificate_attributes.clone()
                    {
                        res.certificate_attributes = Some(certificate_attributes);
                    }
                }
                Tag::CompromiseDate => {
                    res.compromise_date = attributes.compromise_date;
                }
                Tag::CompromiseOccurrenceDate => {
                    res.compromise_occurrence_date = attributes.compromise_occurrence_date;
                }
                Tag::ContactInformation => {
                    attributes
                        .contact_information
                        .clone_into(&mut res.contact_information);
                }
                Tag::CryptographicAlgorithm => {
                    res.cryptographic_algorithm = attributes.cryptographic_algorithm;
                }
                Tag::CryptographicDomainParameters => {
                    res.cryptographic_domain_parameters =
                        attributes.cryptographic_domain_parameters;
                }
                Tag::CryptographicLength => {
                    // Return explicit attribute or (when absent) the key_block recorded length.
                    // If DeleteAttribute cleared both, this will be None.
                    res.cryptographic_length = effective_cryptographic_length;
                }
                Tag::CryptographicParameters => {
                    attributes
                        .cryptographic_parameters
                        .clone_into(&mut res.cryptographic_parameters);
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask;
                }
                Tag::CertificateLength => {
                    // For certificate objects, the length is the DER byte length
                    res.certificate_length = effective_certificate_length;
                }
                Tag::DeactivationDate => {
                    res.deactivation_date = attributes.deactivation_date;
                }
                Tag::DestroyDate => {
                    res.destroy_date = attributes.destroy_date;
                }
                Tag::Digest => {
                    // Prefer any stored Digest attribute; if absent, compute for symmetric keys.
                    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
                    if let Some(digest) = attributes.digest.clone() {
                        res.digest = Some(digest);
                    } else {
                        let computed = match owm.object() {
                            Object::SymmetricKey(SymmetricKey { key_block }) => {
                                // Extract raw key bytes regardless of current KeyFormatType
                                let raw: Option<Vec<u8>> = match key_block.key_value.as_ref() {
                                    Some(KeyValue::Structure { key_material, .. }) => {
                                        match key_material {
                                            KeyMaterial::ByteString(b) => Some(b.to_vec()),
                                            KeyMaterial::TransparentSymmetricKey { key } => {
                                                Some(key.to_vec())
                                            }
                                            _ => None,
                                        }
                                    }
                                    Some(KeyValue::ByteString(b)) => Some(b.to_vec()),
                                    _ => None,
                                };
                                raw.map(|bytes| sha::sha256(&bytes).to_vec())
                            }
                            _ => None,
                        };
                        if let Some(dv) = computed {
                            res.digest = Some(vec![cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::Digest {
                                hashing_algorithm: HashingAlgorithm::SHA256,
                                digest_value: Some(dv),
                                key_format_type: Some(KeyFormatType::Raw),
                            }]);
                        }
                    }
                }
                Tag::Extractable => {
                    // Default to true when unspecified for vector compatibility
                    res.extractable = attributes.extractable.or(Some(true));
                }
                Tag::InitialDate => {
                    res.initial_date = attributes.initial_date;
                }
                Tag::KeyFormatType => {
                    // Stored attribute, else the key block format; transparent RSA, RSA PKCS#8
                    // (the unwrapped storage form) and transparent symmetric formats are
                    // reported as the default format a Get produces (KMIP 2.1 §4.26 Table 81:
                    // PKCS#1 for RSA keys, Raw for symmetric keys).
                    let unwrapped_rsa_key = match owm.object() {
                        Object::PrivateKey(PrivateKey { key_block })
                        | Object::PublicKey(PublicKey { key_block }) => {
                            key_block.key_wrapping_data.is_none()
                                && key_block.cryptographic_algorithm
                                    == Some(CryptographicAlgorithm::RSA)
                        }
                        _ => false,
                    };
                    res.key_format_type = attributes
                        .key_format_type
                        .or_else(|| match owm.object() {
                            Object::SymmetricKey(SymmetricKey { key_block })
                            | Object::PrivateKey(PrivateKey { key_block })
                            | Object::PublicKey(PublicKey { key_block })
                            | Object::SecretData(SecretData { key_block, .. }) => {
                                Some(key_block.key_format_type)
                            }
                            _ => None,
                        })
                        .map(|kft| match kft {
                            KeyFormatType::TransparentRSAPrivateKey
                            | KeyFormatType::TransparentRSAPublicKey => KeyFormatType::PKCS1,
                            KeyFormatType::PKCS8 if unwrapped_rsa_key => KeyFormatType::PKCS1,
                            KeyFormatType::TransparentSymmetricKey => KeyFormatType::Raw,
                            other => other,
                        });
                }
                Tag::LastChangeDate => {
                    res.last_change_date = attributes.last_change_date;
                }
                Tag::Link => {
                    attributes.link.clone_into(&mut res.link);
                }
                Tag::LinkType => {
                    trace!("Get Attributes: computing LinkType set");
                    for link_type in LinkType::iter() {
                        if let Some(link) = attributes.get_link(link_type).as_ref() {
                            res.set_link(link_type, link.clone());
                        }
                    }
                }
                Tag::AlternativeName => {
                    // Propagate AlternativeName structure when present
                    attributes
                        .alternative_name
                        .clone_into(&mut res.alternative_name);
                }
                Tag::Name => {
                    attributes.name.clone_into(&mut res.name);
                }
                Tag::LeaseTime => {
                    res.lease_time = attributes.lease_time;
                }
                Tag::NeverExtractable => {
                    // Default to false when unspecified for vector compatibility
                    res.never_extractable = attributes.never_extractable.or(Some(false));
                }
                Tag::ObjectGroup => {
                    attributes.object_group.clone_into(&mut res.object_group);
                }
                Tag::ObjectType => {
                    res.object_type = attributes
                        .object_type
                        .or_else(|| Some(owm.object().object_type()));
                }
                Tag::OriginalCreationDate => {
                    res.original_creation_date = attributes.original_creation_date;
                }
                Tag::ProcessStartDate => {
                    res.process_start_date = attributes.process_start_date;
                }
                Tag::ProtectStopDate => {
                    res.protect_stop_date = attributes.protect_stop_date;
                }
                Tag::ProtectionStorageMask => {
                    res.protection_storage_masks = attributes.protection_storage_masks.clone();
                }
                Tag::QuantumSafe => {
                    res.quantum_safe = attributes.quantum_safe;
                }
                Tag::RandomNumberGenerator => {
                    attributes
                        .random_number_generator
                        .clone_into(&mut res.random_number_generator);
                }
                Tag::RevocationReason => {
                    attributes
                        .revocation_reason
                        .clone_into(&mut res.revocation_reason);
                }
                Tag::Sensitive => {
                    // Default to false when unspecified
                    res.sensitive = attributes.sensitive.or(Some(false));
                }
                Tag::Fresh => {
                    // Fresh should flip to false once key material has been returned unwrapped.
                    // Prefer the persisted outer attribute (owm.attributes) when it's false,
                    // even if the embedded KeyBlock attributes still show true.
                    let decided = match (owm.attributes().fresh, attributes.fresh) {
                        (Some(false), _) => Some(false),
                        (Some(true), Some(v)) => Some(v),
                        (Some(true), None) => Some(true),
                        (None, v) => v,
                    };
                    res.fresh = decided;
                }
                Tag::State => {
                    res.state = attributes.state;
                }
                Tag::UniqueIdentifier => {
                    // Always authoritative: use the stored object UID from the database row
                    // rather than the embedded attribute value. The embedded value may be a
                    // stale random UUID for re-keyed objects created before the `finalize`
                    // fix stamped the correct new UID into the key material attributes.
                    res.unique_identifier = Some(UniqueIdentifier::TextString(owm.id().to_owned()));
                }
                Tag::ShortUniqueIdentifier => {
                    // KMIP 2.1 §4.56: always has a value, SHOULD be the SHA-256 of the Unique
                    // Identifier; derived when not stored (hex: the Rust type is a String).
                    res.short_unique_identifier = Some(
                        attributes
                            .short_unique_identifier
                            .clone()
                            .unwrap_or_else(|| {
                                hex::encode(openssl::sha::sha256(owm.id().as_bytes()))
                            }),
                    );
                }
                Tag::VendorExtension => {
                    if let Some(vendor_attributes) = attributes.vendor_attributes.clone() {
                        // Filter out server-internal tagging attribute; otherwise return what's present.
                        let filtered: Vec<VendorAttribute> = vendor_attributes
                            .into_iter()
                            .filter(|va| {
                                !(va.vendor_identification == kms.vendor_id()
                                    && va.attribute_name == VENDOR_ATTR_TAG)
                            })
                            .collect();
                        if filtered.is_empty() {
                            res.vendor_attributes = None;
                        } else {
                            res.vendor_attributes = Some(filtered);
                        }
                    }
                }
                Tag::CertificateType => res
                    .certificate_type
                    .clone_from(&attributes.certificate_type),
                Tag::DigitalSignatureAlgorithm => {
                    res.digital_signature_algorithm
                        .clone_from(&attributes.digital_signature_algorithm);
                }
                Tag::KeyValueLocation => {
                    res.key_value_location
                        .clone_from(&attributes.key_value_location);
                }
                Tag::KeyValuePresent => res
                    .key_value_present
                    .clone_from(&attributes.key_value_present),
                Tag::NISTKeyType => res.nist_key_type.clone_from(&attributes.nist_key_type),
                Tag::ObjectGroupMember => {
                    res.object_group_member
                        .clone_from(&attributes.object_group_member);
                }
                Tag::OpaqueDataType => res
                    .opaque_data_type
                    .clone_from(&attributes.opaque_data_type),
                Tag::PKCS12FriendlyName => {
                    attributes
                        .pkcs_12_friendly_name
                        .clone_into(&mut res.pkcs_12_friendly_name);
                }
                Tag::ProtectionLevel => res
                    .protection_level
                    .clone_from(&attributes.protection_level),
                Tag::ProtectionPeriod => res
                    .protection_period
                    .clone_from(&attributes.protection_period),
                Tag::UsageLimits => res.usage_limits.clone_from(&attributes.usage_limits),
                Tag::X509CertificateIdentifier => {
                    res.x_509_certificate_identifier
                        .clone_from(&attributes.x_509_certificate_identifier);
                }
                Tag::X509CertificateIssuer => {
                    attributes
                        .x_509_certificate_issuer
                        .clone_into(&mut res.x_509_certificate_issuer);
                }
                Tag::X509CertificateSubject => {
                    attributes
                        .x_509_certificate_subject
                        .clone_into(&mut res.x_509_certificate_subject);
                }
                Tag::RotateAutomatic => res.rotate_automatic = attributes.rotate_automatic,
                Tag::RotateDate => res.rotate_date = attributes.rotate_date,
                Tag::RotateGeneration => res.rotate_generation = attributes.rotate_generation,
                Tag::RotateInterval => res.rotate_interval = attributes.rotate_interval,
                Tag::RotateLatest => res.rotate_latest = attributes.rotate_latest,
                Tag::RotateName => res.rotate_name.clone_from(&attributes.rotate_name),
                Tag::RotateOffset => res.rotate_offset = attributes.rotate_offset,
                Tag::Tag => {
                    if !tags_already_set {
                        let tags = kms.database.retrieve_tags(owm.id()).await?;
                        res.set_tags(kms.vendor_id(), tags)?;
                        tags_already_set = true;
                    }
                }
                x => {
                    // we ignore Tags which do not match to attributes
                    trace!("Ignoring tag {x:?} which does not match to an attribute");
                }
            },
        }
    }
    debug!(
        "Retrieved Attributes for {} {}, tags {:?}",
        owm.object().object_type(),
        owm.id(),
        res.get_tags(kms.vendor_id())
    );

    Ok(res)
}
