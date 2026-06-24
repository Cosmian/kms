use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attribute,
            kmip_objects::ObjectType,
            kmip_operations::{SetAttribute, SetAttributeResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SECS_PER_DAY},
};
use cosmian_logger::{debug, trace};
use time::OffsetDateTime;

/// `SECS_PER_DAY - 1`, used for ceiling integer division of seconds into whole days.
const SECS_PER_DAY_MINUS_ONE: i64 = SECS_PER_DAY - 1;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::has_prefix},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Extract the PKCS#11 `key_id` from an HSM UID of the form
/// `hsm::<model>::<slot_id>::<key_id>`.
///
/// Returns `None` if the UID cannot be parsed.
fn extract_hsm_key_id(uid: &str) -> Option<&str> {
    let prefix = has_prefix(uid)?;
    // Strip "hsm::<model>::" to get "<slot_id>::<key_id>"
    let rest = uid.strip_prefix(&format!("{prefix}::"))?;
    // Skip the slot_id segment
    rest.split_once("::").map(|(_, key_id)| key_id)
}

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

    // Read-only guard — must be checked before the DB round-trip.
    match &request.new_attribute {
        Attribute::State(_)
        | Attribute::RotateGeneration(_)
        | Attribute::RotateDate(_)
        | Attribute::RotateLatest(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "DENIED: this attribute is server-managed and cannot be set by the user".to_owned(),
            ));
        }
        Attribute::RotateName(name) if name.contains('@') => {
            return Err(KmsError::InvalidRequest(
                "SetAttribute: rotate_name must not contain '@' (reserved for keyset versioning)"
                    .to_owned(),
            ));
        }
        _ => {}
    }

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::SetAttribute,
        kms,
        user,
    ))
    .await?;
    trace!("Set Attribute: Retrieved target object");

    // Capture HSM-rotation values before the `match_set_attribute!` macro may
    // partially move `request.new_attribute`.  We do this here — after object
    // retrieval — so we can inspect `owm.id()` to confirm it is an HSM key.
    let (hsm_rotate_name, hsm_rotate_interval_secs) = if has_prefix(owm.id()).is_some() {
        match &request.new_attribute {
            Attribute::RotateOffset(_) => {
                return Err(KmsError::NotSupported(
                    "SetAttribute: rotate_offset is not supported for HSM keys".to_owned(),
                ));
            }
            Attribute::RotateName(n) => (Some(n.clone()), None::<i64>),
            Attribute::RotateInterval(n) => (None::<String>, Some(*n)),
            _ => (None, None),
        }
    } else {
        (None, None)
    };

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
            RotateAutomatic => rotate_automatic,
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

    // HSM-specific: propagate rotation attributes directly to PKCS#11 storage.
    // `HsmStore::update_object` is a no-op for attributes (the HSM has no
    // generic KV attribute storage), so we must explicitly write CKA_LABEL and
    // CKA_START_DATE / CKA_END_DATE when the caller sets rotation metadata.
    if let Some(rotate_name) = hsm_rotate_name {
        // Register key in a keyset by writing CKA_LABEL at generation 0.
        let key_id = extract_hsm_key_id(owm.id()).ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "SetAttribute: cannot parse key_id from HSM UID '{}'",
                owm.id()
            ))
        })?;
        let label = format!("{rotate_name}::0::{key_id}::latest");
        trace!(
            "SetAttribute: writing CKA_LABEL '{}' on HSM key '{}'",
            label,
            owm.id()
        );
        kms.database.set_key_label(owm.id(), &label).await?;
    } else if let Some(interval_secs) = hsm_rotate_interval_secs {
        // CKA_START_DATE / CKA_END_DATE are PKCS#11 CK_DATE fields (year/month/day only —
        // no sub-day precision).  These dates ARE the scheduling signal used by
        // HsmStore::find_due_for_rotation to determine when to auto-rotate the key;
        // HsmStore::update_object is a no-op for KMIP attributes, so there is no other
        // persistent store for rotate_interval on HSM keys.
        if interval_secs == 0 {
            // RotateInterval = 0 disables auto-rotation: clear the PKCS#11 dates so
            // HsmStore::find_due_for_rotation no longer considers this key overdue.
            trace!(
                "SetAttribute: clearing CKA_START_DATE / CKA_END_DATE on HSM key '{}' (rotation disabled)",
                owm.id()
            );
            kms.database
                .set_key_rotation_dates(owm.id(), None, None)
                .await?;
        } else if interval_secs < SECS_PER_DAY {
            // PKCS#11 CK_DATE only stores year/month/day.  A sub-day interval would map
            // to end_date = today (0 whole days), causing the key to be immediately due
            // for rotation on every scheduler tick.  Reject it explicitly so callers get
            // a clear error instead of unexpected behaviour.
            return Err(KmsError::InvalidRequest(format!(
                "SetAttribute: RotateInterval for HSM key '{}' must be at least 86400 seconds \
                 (1 day) because PKCS#11 CK_DATE has day granularity only. Got {interval_secs} s.",
                owm.id()
            )));
        } else {
            let today = OffsetDateTime::now_utc().date();
            // Ceiling-divide so that an interval that is not an exact multiple of
            // SECS_PER_DAY (86 400) does not map to end_date = today (which would
            // trigger immediate rotation).
            let days = (interval_secs + SECS_PER_DAY_MINUS_ONE) / SECS_PER_DAY;
            let end_date = today + time::Duration::days(days);
            trace!(
                "SetAttribute: writing CKA_START_DATE={} CKA_END_DATE={} on HSM key '{}'",
                today,
                end_date,
                owm.id()
            );
            kms.database
                .set_key_rotation_dates(owm.id(), Some(today), Some(end_date))
                .await?;
        }
    }

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
