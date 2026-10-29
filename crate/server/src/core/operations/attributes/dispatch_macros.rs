/// Invokes one of the `match_*_attribute!` macros below with the simple
/// (`Variant => field`) arms shared by Add, Set, Modify and Delete Attribute,
/// followed by the operation-specific simple arms and the custom arms.
///
/// `ActivationDate` and `CryptographicLength` are deliberately not shared:
/// Modify handles the former and Delete the latter as custom arms.
macro_rules! with_common_simple_attributes {
    (
        $macro_name:ident! { $($head:tt)* }
        simple { $($extra:tt)* }
        custom { $($custom:tt)* }
    ) => {
        $macro_name! {
            $($head)*
            simple {
                CryptographicAlgorithm => cryptographic_algorithm,
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
                $($extra)*
            }
            custom { $($custom)* }
        }
    };
}

/// Generate the full match block for `AddAttribute` with simple (check-then-assign) arms
/// and custom arms for special-case attributes.
#[allow(unused_macros)]
macro_rules! match_add_attribute {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    trace!(concat!(stringify!($variant), ": {:?}"), value);
                    if $attrs.$field.is_some() {
                        return Err(KmsError::InvalidRequest(
                            concat!(stringify!($variant), " already exists").to_owned(),
                        ));
                    }
                    $attrs.$field = Some(value);
                }
            )*
            $($custom)*
        }
    };
}

/// Generate the full match block for `SetAttribute`/`ModifyAttribute` with simple
/// (unconditional assign) arms and custom arms for special-case attributes.
/// The `$prefix` is included in the trace output (e.g. "`SetAttribute`" or "`ModifyAttribute`").
#[allow(unused_macros)]
macro_rules! match_set_attribute {
    (
        $prefix:expr, $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    trace!(concat!($prefix, ": ", stringify!($variant), ": {:?}"), value);
                    $attrs.$field = Some(value);
                }
            )*
            $($custom)*
        }
    };
}

/// Generate the full match block for `DeleteAttribute` with simple (compare-then-clear) arms
/// and custom arms for special-case attributes.
#[allow(unused_macros)]
macro_rules! match_delete_attribute {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    if Some(value) == $attrs.$field {
                        $attrs.$field = None;
                    }
                }
            )*
            $($custom)*
        }
    };
}

/// Deletes an attribute identified by its `Tag` (rather than by value).
///
/// `DeleteAttribute` may reference an attribute either by value
/// (`CurrentAttribute`) or purely by name (`AttributeReference`). This macro
/// covers the name-based form, clearing the matching field unconditionally.
///
/// KMIP 1.4 §4.16 / KMIP 2.1 §6.1.13.
#[allow(unused_macros)]
macro_rules! match_delete_attribute_by_tag {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Tag::$variant => {
                    $attrs.$field = None;
                }
            )*
            $($custom)*
        }
    };
}
