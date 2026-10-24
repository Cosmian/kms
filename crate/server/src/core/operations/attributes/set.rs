use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attribute,
            kmip_objects::ObjectType,
            kmip_operations::{SetAttribute, SetAttributeResponse},
            kmip_types::UniqueIdentifier,
        },
        time_normalize,
    },
    cosmian_kms_interfaces::SECS_PER_DAY,
};
use cosmian_logger::{debug, trace};
use time::OffsetDateTime;

/// `SECS_PER_DAY - 1`, used for ceiling integer division of seconds into whole days.
const SECS_PER_DAY_MINUS_ONE: i64 = SECS_PER_DAY - 1;

use super::policy::{
    check_extractable_latch, check_grant, check_read_only, check_rotate_name,
    check_vendor_attribute, read_only_error,
};
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

/// Extract the PKCS#11 `key_id` from an HSM UID of the form
/// `hsm::<model>::<slot_id>::<key_id>`.
///
/// Returns `None` if the UID cannot be parsed.
fn extract_hsm_key_id(uid: &str) -> Option<&str> {
    let ObjectHandle::Hsm { .. } = ObjectHandle::from(uid) else {
        return None;
    };
    // key_id is always the last "::"-delimited segment of an HSM UID.
    uid.rsplit("::").next()
}

/// Compute the full base UID for an HSM key: `hsm::<prefix>::<slot>::<key_id_without_@N>`.
///
/// This is the canonical `rotate_name` for HSM-resident keys — it embeds the slot ID
/// and is therefore unique across HSM slots.
fn hsm_base_uid(uid: &str) -> Option<String> {
    ObjectHandle::from(uid)
        .hsm_parts()
        .ok()
        .map(|p| p.full_base_uid())
}

pub(crate) async fn set_attribute(
    kms: &KMS,
    request: SetAttribute,
    user: &UserId,
) -> KResult<SetAttributeResponse> {
    debug!("SetAttribute request");

    // there must be an identifier
    let object_handle = from_request(request.unique_identifier.as_ref(), "Set Attribute")?;

    // Read-only guard — must be checked before the DB round-trip.
    check_read_only(request.new_attribute.tag(), KmipOperation::SetAttribute)?;
    check_rotate_name(&request.new_attribute, "SetAttribute")?;
    check_vendor_attribute(&request.new_attribute, KmipOperation::SetAttribute)?;

    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::SetAttribute,
        kms,
        user,
    ))
    .await?;
    let owm = Arc::unwrap_or_clone(owm);
    trace!("Set Attribute: Retrieved target object");

    // For SQL objects (non-HSM): rotate_name must equal the object's UID.
    // This enforces the gen-0 UID = keyset name invariant for deterministic @N addressing.
    if !ObjectHandle::from(owm.id()).is_hsm() {
        if let Attribute::RotateName(name) = &request.new_attribute {
            let object_uid = owm.id();
            if name.as_str() != object_uid {
                return Err(KmsError::InvalidRequest(format!(
                    "SetAttribute: rotate_name ('{name}') must equal the object's UID \
                     ('{object_uid}') — create the object with the keyset name as its ID"
                )));
            }
        }
    }

    // For HSM keys: rotate_name must be the key's full base UID (hsm::slot::key_id without
    // any @N suffix).  The slot ID in the UID guarantees uniqueness across HSM slots,
    // preventing keyset name collisions when multiple slots host keys with the same name.
    if ObjectHandle::from(owm.id()).is_hsm() {
        if let Attribute::RotateName(name) = &request.new_attribute {
            let expected = hsm_base_uid(owm.id()).ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "SetAttribute: cannot derive base UID from HSM key '{}'",
                    owm.id()
                ))
            })?;
            if name.as_str() != expected {
                return Err(KmsError::InvalidRequest(format!(
                    "SetAttribute: for HSM keys, rotate_name must be the key's base UID \
                     ('{expected}'), not '{name}'"
                )));
            }
        }
    }

    // Capture rotation values before the `match_set_attribute!` macro may
    // partially move `request.new_attribute`.
    let is_sql = !ObjectHandle::from(owm.id()).is_hsm();
    let is_setting_rotate_name_on_sql =
        is_sql && matches!(&request.new_attribute, Attribute::RotateName(_));
    let is_setting_positive_rotate_interval_on_sql =
        is_sql && matches!(&request.new_attribute, Attribute::RotateInterval(n) if *n > 0);

    let (hsm_rotate_name, hsm_rotate_interval_secs) = if is_sql {
        (None, None)
    } else {
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
    };
    check_grant(
        kms,
        &owm,
        user,
        KmipOperation::SetAttribute,
        request.new_attribute.tag(),
    )
    .await?;

    // KMIP 2.1 §4.1: Activation Date is client-settable only while Pre-Active.
    if matches!(&request.new_attribute, Attribute::ActivationDate(_))
        && owm.state() != State::PreActive
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Wrong_Key_Lifecycle_State,
            format!(
                "SetAttribute: ActivationDate can only be set on a Pre-Active object (current \
                 state: {:?})",
                owm.state()
            ),
        ));
    }

    let (id, mut object, mut attributes) = owm.into_parts();
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
            Fresh => fresh,
            InitialDate => initial_date,
            KeyFormatType => key_format_type,
            KeyValueLocation => key_value_location,
            KeyValuePresent => key_value_present,
            LastChangeDate => last_change_date,
            LeaseTime => lease_time,
            NistKeyType => nist_key_type,
            ObjectGroupMember => object_group_member,
            OpaqueDataType => opaque_data_type,
            OriginalCreationDate => original_creation_date,
            Pkcs12FriendlyName => pkcs_12_friendly_name,
            ProcessStartDate => process_start_date,
            ProtectStopDate => protect_stop_date,
            ProtectionLevel => protection_level,
            ProtectionPeriod => protection_period,
            ProtectionStorageMask => protection_storage_masks,
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
            Attribute::AlwaysSensitive(_)
            | Attribute::NeverExtractable(_)
            | Attribute::State(_)
            | Attribute::Digest(_) => {
                // Defensive: already refused by `check_read_only`.
                return Err(read_only_error(KmipOperation::SetAttribute));
            }
            Attribute::Sensitive(sensitive) => {
                // Setting Sensitive also (re)computes the server-managed
                // AlwaysSensitive attribute (KMIP 2.1 §4.3).
                trace!("Set Attribute: Sensitive: {:?}", sensitive);
                attributes.apply_sensitive(sensitive);
            }
            Attribute::Extractable(extractable) => {
                trace!("Set Attribute: Extractable: {:?}", extractable);
                check_extractable_latch(&attributes, extractable, KmipOperation::SetAttribute)?;
                attributes.apply_extractable(extractable);
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
            Attribute::Name(name) => {
                trace!("Set Attribute: Name: {}", name);
                let names = attributes.name.get_or_insert(vec![]);
                match names.len() {
                    0 => names.push(name),
                    1 => {
                        if let Some(first) = names.first_mut() {
                            *first = name;
                        }
                    }
                    _ => {
                        return Err(KmsError::Kmip21Error(
                            ErrorReason::Multi_Valued_Attribute,
                            "SetAttribute: Name has several instances; use ModifyAttribute with a \
                             Current Attribute or DeleteAttribute"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
    }

    attributes.last_change_date = Some(time_normalize()?);
    let tags = kms.database.retrieve_tags(&id).await?;

    // For SQL keys: initialise keyset metadata when rotate_name is first set.
    // rotate_generation and rotate_latest are server-managed (read-only guard above),
    // so they can only be initialised here, not by the user directly.
    if is_setting_rotate_name_on_sql {
        if attributes.rotate_generation.is_none() {
            attributes.rotate_generation = Some(0);
        }
        if attributes.rotate_latest.is_none() {
            attributes.rotate_latest = Some(true);
        }
    }

    // When the client sets RotateInterval > 0 on a SQL key without also setting
    // RotateAutomatic, implicitly enable auto-rotation.  The scheduler's
    // `find_due_for_rotation` query filters on `rotate_automatic = true`, so a key
    // that only has an interval set would otherwise never be rotated.
    // An explicit `rotate_automatic = Some(false)` is respected and not overridden.
    if is_setting_positive_rotate_interval_on_sql && attributes.rotate_automatic.is_none() {
        debug!(
            "SetAttribute: implicitly enabling rotate_automatic for key '{id}' (RotateInterval > 0 with no explicit RotateAutomatic)"
        );
        attributes.rotate_automatic = Some(true);
    }
    // `HsmStore::update_object` is a no-op for attributes (the HSM has no
    // generic KV attribute storage), so we must explicitly write CKA_LABEL and
    // CKA_START_DATE / CKA_END_DATE when the caller sets rotation metadata.
    if let Some(rotate_name) = hsm_rotate_name {
        // Register key in a keyset by writing CKA_LABEL at generation 0.
        let key_id = extract_hsm_key_id(&id).ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "SetAttribute: cannot parse key_id from HSM UID '{id}'"
            ))
        })?;
        let label = format!("{rotate_name}::0::{key_id}@latest");
        trace!("SetAttribute: writing CKA_LABEL '{label}' on HSM key '{id}'");
        kms.database.set_key_label(&id, &label).await?;
        kms.database.invalidate_rotate_name_cache(&rotate_name);
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
                "SetAttribute: clearing CKA_START_DATE / CKA_END_DATE on HSM key '{id}' (rotation disabled)"
            );
            kms.database.set_key_rotation_dates(&id, None, None).await?;
        } else if interval_secs < SECS_PER_DAY {
            // PKCS#11 CK_DATE only stores year/month/day.  A sub-day interval would map
            // to end_date = today (0 whole days), causing the key to be immediately due
            // for rotation on every scheduler tick.  Reject it explicitly so callers get
            // a clear error instead of unexpected behaviour.
            return Err(KmsError::InvalidRequest(format!(
                "SetAttribute: RotateInterval for HSM key '{id}' must be at least 86400 seconds \
                 (1 day) because PKCS#11 CK_DATE has day granularity only. Got {interval_secs} s."
            )));
        } else {
            let today = OffsetDateTime::now_utc().date();
            // Ceiling-divide so that an interval that is not an exact multiple of
            // SECS_PER_DAY (86 400) does not map to end_date = today (which would
            // trigger immediate rotation).
            let days = (interval_secs + SECS_PER_DAY_MINUS_ONE) / SECS_PER_DAY;
            let end_date = today + time::Duration::days(days);
            trace!(
                "SetAttribute: writing CKA_START_DATE={today} CKA_END_DATE={end_date} on HSM key '{id}'"
            );
            kms.database
                .set_key_rotation_dates(&id, Some(today), Some(end_date))
                .await?;
        }
    }

    match object.object_type() {
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
            if let Ok(object_attributes) = object.attributes_mut() {
                object_attributes.clone_from(&attributes);
                debug!("Synchronized embedded object attributes");
            }
        }
        _ => {
            trace!(
                "Set Attribute: Object type {:?} does not have attributes (nor key block)",
                object.object_type()
            );
        }
    }

    debug!("Set object attribute");
    kms.database
        .update_object(&id, &object, &attributes, Some(&tags))
        .await?;

    Ok(SetAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(id),
    })
}
