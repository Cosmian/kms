use std::collections::HashSet;

use cosmian_kmip::kmip_2_1::{self, kmip_objects::Object};
use cosmian_kms_client::cosmian_kmip::kmip_0::kmip_messages::ResponseMessage;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::xml::{deviations::Ctx, versioned::compare_versioned_batch_item},
};

/// Compare expected and actual KMIP responses on essential fields and payloads.
///
/// `vector` is the vector file stem and `request` the 0-based response index, used to
/// look up accepted deviations; `generated_uids` are the objects the server generated so far.
pub(crate) fn compare_response_messages(
    vector: &str,
    request: usize,
    generated_uids: &HashSet<String>,
    expected: &ResponseMessage,
    actual: &ResponseMessage,
) -> KmsCliResult<()> {
    let ctx = |batch| Ctx {
        vector,
        request,
        batch,
        generated_uids,
        object_generated: false,
    };
    // Time stamp and other header fields are server-generated and stay uncompared.
    let (eh, ah) = (&expected.response_header, &actual.response_header);
    let (ev, av) = (&eh.protocol_version, &ah.protocol_version);
    if (ev.protocol_version_major, ev.protocol_version_minor)
        != (av.protocol_version_major, av.protocol_version_minor)
        && !ctx(0).allows("protocol_version")
    {
        return Err(KmsCliError::Default(format!(
            "protocol_version mismatch expected={}.{} actual={}.{}",
            ev.protocol_version_major,
            ev.protocol_version_minor,
            av.protocol_version_major,
            av.protocol_version_minor
        )));
    }
    if eh.batch_count != ah.batch_count {
        return Err(KmsCliError::Default(format!(
            "batch_count mismatch expected={} actual={}",
            eh.batch_count, ah.batch_count
        )));
    }
    if expected.batch_item.len() != actual.batch_item.len() {
        return Err(KmsCliError::Default(format!(
            "batch size mismatch expected={} actual={}",
            expected.batch_item.len(),
            actual.batch_item.len()
        )));
    }

    for (batch, (exp_item, act_item)) in expected
        .batch_item
        .iter()
        .zip(actual.batch_item.iter())
        .enumerate()
    {
        compare_versioned_batch_item(&ctx(batch), exp_item, act_item)?;
    }

    Ok(())
}

// Deep compare of KMIP Object, including nested KeyBlock, KeyValue, and Attributes when present
pub(crate) fn compare_object(ctx: &Ctx, expected: &Object, actual: &Object) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Object type mismatch expected={expected} actual={actual}"
        )));
    }

    match (expected, actual) {
        (Object::PGPKey(e), Object::PGPKey(a)) => {
            if e.pgp_key_version != a.pgp_key_version {
                return Err(KmsCliError::Default(format!(
                    "PGPKey.pgp_key_version expected={} actual={}",
                    e.pgp_key_version, a.pgp_key_version
                )));
            }
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        (Object::SecretData(e), Object::SecretData(a)) => {
            if e.secret_data_type != a.secret_data_type {
                return Err(KmsCliError::Default(format!(
                    "SecretData.secret_data_type expected={:?} actual={:?}",
                    e.secret_data_type, a.secret_data_type
                )));
            }
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        (Object::SplitKey(e), Object::SplitKey(a)) => {
            if e.split_key_parts != a.split_key_parts {
                return Err(KmsCliError::Default(format!(
                    "SplitKey.split_key_parts expected={} actual={}",
                    e.split_key_parts, a.split_key_parts
                )));
            }
            if e.key_part_identifier != a.key_part_identifier {
                return Err(KmsCliError::Default(format!(
                    "SplitKey.key_part_identifier expected={} actual={}",
                    e.key_part_identifier, a.key_part_identifier
                )));
            }
            if e.split_key_threshold != a.split_key_threshold {
                return Err(KmsCliError::Default(format!(
                    "SplitKey.split_key_threshold expected={} actual={}",
                    e.split_key_threshold, a.split_key_threshold
                )));
            }
            if e.split_key_method != a.split_key_method {
                return Err(KmsCliError::Default(format!(
                    "SplitKey.split_key_method expected={:?} actual={:?}",
                    e.split_key_method, a.split_key_method
                )));
            }
            if e.prime_field_size != a.prime_field_size {
                return Err(KmsCliError::Default(format!(
                    "SplitKey.prime_field_size expected={:?} actual={:?}",
                    e.prime_field_size, a.prime_field_size
                )));
            }
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        (Object::PrivateKey(e), Object::PrivateKey(a)) => {
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        (Object::PublicKey(e), Object::PublicKey(a)) => {
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        (Object::SymmetricKey(e), Object::SymmetricKey(a)) => {
            compare_key_block(ctx, &e.key_block, &a.key_block)?;
        }
        // Should never happen due to discriminant check, but keep a safe fallback
        _ => {
            if expected != actual {
                return Err(KmsCliError::Default(format!(
                    "Object mismatch expected={expected} actual={actual}"
                )));
            }
        }
    }
    Ok(())
}

// Normalize KeyWrappingData for comparison: per spec, absence of encoding_option
// implies TTLV encoding. Treat None == Some(TTLVEncoding).
fn normalize_kwd(
    kwd: &kmip_2_1::kmip_data_structures::KeyWrappingData,
) -> kmip_2_1::kmip_data_structures::KeyWrappingData {
    let mut n = kwd.clone();
    if n.encoding_option.is_none() {
        n.encoding_option = Some(kmip_2_1::kmip_types::EncodingOption::TTLVEncoding);
    }
    n
}

pub(crate) fn compare_key_block(
    ctx: &Ctx,
    expected: &kmip_2_1::kmip_data_structures::KeyBlock,
    actual: &kmip_2_1::kmip_data_structures::KeyBlock,
) -> KmsCliResult<()> {
    if expected.key_format_type != actual.key_format_type
        && !ctx.allows("key_block.key_format_type")
    {
        return Err(KmsCliError::Default(format!(
            "KeyBlock.key_format_type expected={:?} actual={:?}",
            expected.key_format_type, actual.key_format_type
        )));
    }
    if expected.key_compression_type != actual.key_compression_type {
        return Err(KmsCliError::Default(format!(
            "KeyBlock.key_compression_type expected={:?} actual={:?}",
            expected.key_compression_type, actual.key_compression_type
        )));
    }

    match (&expected.key_value, &actual.key_value) {
        (None, None) => {}
        (Some(e), Some(a)) => compare_key_value(ctx, e, a)?,
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_value expected=None actual=Some".to_owned(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_value expected=Some actual=None".to_owned(),
            ));
        }
    }

    if expected.cryptographic_algorithm != actual.cryptographic_algorithm {
        return Err(KmsCliError::Default(format!(
            "KeyBlock.cryptographic_algorithm expected={:?} actual={:?}",
            expected.cryptographic_algorithm, actual.cryptographic_algorithm
        )));
    }
    if expected.cryptographic_length != actual.cryptographic_length {
        return Err(KmsCliError::Default(format!(
            "KeyBlock.cryptographic_length expected={:?} actual={:?}",
            expected.cryptographic_length, actual.cryptographic_length
        )));
    }

    match (&expected.key_wrapping_data, &actual.key_wrapping_data) {
        (None, None) => {}
        (Some(e), Some(a)) => {
            if e != a && normalize_kwd(e) != normalize_kwd(a) {
                return Err(KmsCliError::Default(
                    "KeyBlock.key_wrapping_data mismatch".to_owned(),
                ));
            }
        }
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_wrapping_data expected=None actual=Some".to_owned(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_wrapping_data expected=Some actual=None".to_owned(),
            ));
        }
    }

    Ok(())
}

/// Key bytes must match exactly. An empty or `$KEY_MATERIAL_` expected value is a vector
/// placeholder (V21 placeholders were already replaced by the actual bytes) and accepts any;
/// a server-generated key only has to match in length.
fn compare_key_bytes(ctx: &Ctx, what: &str, expected: &[u8], actual: &[u8]) -> KmsCliResult<()> {
    let placeholder = expected.is_empty() || expected.starts_with(b"$KEY_MATERIAL_");
    let differs = if ctx.object_generated {
        expected.len() != actual.len()
    } else {
        expected != actual
    };
    if !placeholder && differs && !ctx.allows("key_value.bytes") {
        return Err(KmsCliError::Default(format!(
            "{what} bytes mismatch expected_len={} actual_len={}",
            expected.len(),
            actual.len()
        )));
    }
    Ok(())
}

pub(crate) fn compare_key_value(
    ctx: &Ctx,
    expected: &kmip_2_1::kmip_data_structures::KeyValue,
    actual: &kmip_2_1::kmip_data_structures::KeyValue,
) -> KmsCliResult<()> {
    use std::mem::discriminant;

    use kmip_2_1::kmip_data_structures::{KeyMaterial, KeyValue};
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "KeyValue type mismatch expected={expected} actual={actual}"
        )));
    }
    match (expected, actual) {
        (KeyValue::ByteString(eb), KeyValue::ByteString(ab)) => {
            compare_key_bytes(ctx, "KeyValue::ByteString", eb, ab)?;
        }
        (
            KeyValue::Structure {
                key_material: ekm,
                attributes: ea,
            },
            KeyValue::Structure {
                key_material: akm,
                attributes: aa,
            },
        ) => {
            // Transparent symmetric key bytes compare against raw bytes.
            let symmetric_vs_raw = matches!(
                (ekm, akm),
                (
                    KeyMaterial::TransparentSymmetricKey { .. },
                    KeyMaterial::ByteString(_)
                )
            );
            if !symmetric_vs_raw && discriminant(ekm) != discriminant(akm) {
                return Err(KmsCliError::Default(format!(
                    "KeyMaterial type mismatch expected={ekm} actual={akm}"
                )));
            }

            match (ekm, akm) {
                (KeyMaterial::ByteString(e), KeyMaterial::ByteString(a)) => {
                    compare_key_bytes(ctx, "KeyMaterial::ByteString", e, a)?;
                }
                (KeyMaterial::TransparentSymmetricKey { key: e }, KeyMaterial::ByteString(a)) => {
                    compare_key_bytes(ctx, "KeyMaterial::TransparentSymmetricKey", e, a)?;
                }
                (
                    KeyMaterial::TransparentSymmetricKey { key: ek },
                    KeyMaterial::TransparentSymmetricKey { key: ak },
                ) => {
                    compare_key_bytes(ctx, "KeyMaterial::TransparentSymmetricKey", ek, ak)?;
                }
                (
                    KeyMaterial::TransparentRSAPublicKey {
                        modulus: em,
                        public_exponent: ee,
                    },
                    KeyMaterial::TransparentRSAPublicKey {
                        modulus: am,
                        public_exponent: ae,
                    },
                ) => {
                    if em != am || ee != ae {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentRSAPublicKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentRSAPrivateKey {
                        modulus: em,
                        private_exponent: e_priv,
                        public_exponent: e_pub,
                        p: ep,
                        q: eq_,
                        prime_exponent_p: e_pep,
                        prime_exponent_q: e_peq,
                        c_r_t_coefficient: e_crt,
                    },
                    KeyMaterial::TransparentRSAPrivateKey {
                        modulus: am,
                        private_exponent: a_priv,
                        public_exponent: a_pub,
                        p: ap,
                        q: aq,
                        prime_exponent_p: a_pep,
                        prime_exponent_q: a_peq,
                        c_r_t_coefficient: a_crt,
                    },
                ) => {
                    if em != am
                        || e_priv != a_priv
                        || e_pub != a_pub
                        || ep != ap
                        || eq_ != aq
                        || e_pep != a_pep
                        || e_peq != a_peq
                        || e_crt != a_crt
                    {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentRSAPrivateKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentDSAPrivateKey {
                        p: ep,
                        q: eq_,
                        g: eg,
                        x: ex,
                    },
                    KeyMaterial::TransparentDSAPrivateKey {
                        p: ap,
                        q: aq,
                        g: ag,
                        x: ax,
                    },
                ) => {
                    if ep != ap || eq_ != aq || eg != ag || ex != ax {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentDSAPrivateKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentDSAPublicKey {
                        p: ep,
                        q: eq_,
                        g: eg,
                        y: ey,
                    },
                    KeyMaterial::TransparentDSAPublicKey {
                        p: ap,
                        q: aq,
                        g: ag,
                        y: ay,
                    },
                ) => {
                    if ep != ap || eq_ != aq || eg != ag || ey != ay {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentDSAPublicKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentDHPrivateKey {
                        p: ep,
                        q: eq_,
                        g: eg,
                        j: ej,
                        x: ex,
                    },
                    KeyMaterial::TransparentDHPrivateKey {
                        p: ap,
                        q: aq,
                        g: ag,
                        j: aj,
                        x: ax,
                    },
                ) => {
                    if ep != ap || eq_ != aq || eg != ag || ej != aj || ex != ax {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentDHPrivateKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentDHPublicKey {
                        p: ep,
                        q: eq_,
                        g: eg,
                        j: ej,
                        y: ey,
                    },
                    KeyMaterial::TransparentDHPublicKey {
                        p: ap,
                        q: aq,
                        g: ag,
                        j: aj,
                        y: ay,
                    },
                ) => {
                    if ep != ap || eq_ != aq || eg != ag || ej != aj || ey != ay {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentDHPublicKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentECPrivateKey {
                        recommended_curve: erc,
                        d: ed,
                    },
                    KeyMaterial::TransparentECPrivateKey {
                        recommended_curve: arc,
                        d: ad,
                    },
                ) => {
                    if erc != arc || ed != ad {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentECPrivateKey mismatch".to_owned(),
                        ));
                    }
                }
                (
                    KeyMaterial::TransparentECPublicKey {
                        recommended_curve: erc,
                        q_string: eqs,
                    },
                    KeyMaterial::TransparentECPublicKey {
                        recommended_curve: arc,
                        q_string: aqs,
                    },
                ) => {
                    if erc != arc || eqs != aqs {
                        return Err(KmsCliError::Default(
                            "KeyMaterial::TransparentECPublicKey mismatch".to_owned(),
                        ));
                    }
                }
                _ => {
                    if ekm != akm {
                        return Err(KmsCliError::Default("KeyMaterial mismatch".to_owned()));
                    }
                }
            }

            match (ea, aa) {
                // If the expected vector doesn't specify attributes, accept whatever the server returns
                (None, _) => {}
                (Some(ea), Some(aa)) => {
                    compare_attributes(ctx, ea, aa)?;
                }
                (Some(_), None) => {
                    return Err(KmsCliError::Default(
                        "KeyValue.attributes expected=Some actual=None".to_owned(),
                    ));
                }
            }
        }
        // Cross-variant mismatch should have been caught by the discriminant check above,
        // but include an explicit arm for exhaustiveness.
        _ => {
            return Err(KmsCliError::Default("KeyValue variant mismatch".to_owned()));
        }
    }
    Ok(())
}

// Deep compare for Attributes: every field is compared by presence and value, except
// server-generated timestamps (`initial_date`, `last_change_date`) and the vendor
// attributes the server adds on its own.
pub(crate) fn compare_attributes(
    ctx: &Ctx,
    expected: &kmip_2_1::kmip_attributes::Attributes,
    actual: &kmip_2_1::kmip_attributes::Attributes,
) -> KmsCliResult<()> {
    let (e, a) = (expected, actual);

    macro_rules! mismatch {
        ($field:ident) => {
            Err(KmsCliError::Default(format!(
                "Attributes.{} mismatch expected={:?} actual={:?}",
                stringify!($field),
                e.$field,
                a.$field
            )))
        };
    }
    macro_rules! allowed {
        ($field:ident) => {
            ctx.allows(concat!("attributes.", stringify!($field)))
        };
    }
    macro_rules! cmp_opt {
        ($($field:ident),+ $(,)?) => {$(
            if e.$field != a.$field && !allowed!($field) {
                return mismatch!($field);
            }
        )+};
    }
    // `$NOW` and `$NOW-<delta>` parse to the UNIX epoch: the server's real date must be present.
    macro_rules! cmp_date {
        ($($field:ident),+ $(,)?) => {$(
            let ok = if e.$field == Some(time::OffsetDateTime::UNIX_EPOCH) {
                a.$field.is_some()
            } else {
                e.$field == a.$field
            };
            if !ok && !allowed!($field) {
                return mismatch!($field);
            }
        )+};
    }

    // Systematic deviation (`UNIMPLEMENTED_ATTRIBUTES`): the server never sets these, so an
    // absent actual value is accepted; a present one must match.
    macro_rules! cmp_unimplemented {
        ($($field:ident),+) => {$(
            if e.$field != a.$field && a.$field.is_some() && !allowed!($field) {
                return mismatch!($field);
            }
        )+};
    }
    cmp_unimplemented!(lease_time, protection_storage_masks);
    cmp_date!(activation_date, deactivation_date, destroy_date);
    if ctx.object_generated {
        // Server creation time and digest of fresh key material: presence and form only.
        if e.original_creation_date.is_some() != a.original_creation_date.is_some()
            && !allowed!(original_creation_date)
        {
            return mismatch!(original_creation_date);
        }
        let digest_form = |d: &Option<Vec<kmip_2_1::kmip_types::Digest>>| {
            d.as_ref().map(|d| {
                d.iter()
                    .map(|d| {
                        (
                            d.hashing_algorithm,
                            d.key_format_type,
                            d.digest_value.as_ref().map(Vec::len),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        };
        if digest_form(&e.digest) != digest_form(&a.digest) && !allowed!(digest) {
            return mismatch!(digest);
        }
    } else {
        cmp_date!(original_creation_date);
        cmp_opt!(digest);
    }
    // KMIP 1.3+ 3.44: the server sets Random Number Generator on objects it generates; a vector
    // recorded on a reference server that did not may omit it. A value it does give must match.
    let rng_omitted = ctx.object_generated && e.random_number_generator.is_none();
    if !rng_omitted {
        cmp_opt!(random_number_generator);
    }
    cmp_opt!(
        alternative_name,
        always_sensitive,
        application_specific_information,
        archive_date,
        attribute_index,
        certificate_attributes,
        certificate_type,
        certificate_length,
        comment,
        compromise_date,
        compromise_occurrence_date,
        contact_information,
        critical,
        cryptographic_algorithm,
        cryptographic_domain_parameters,
        cryptographic_length,
        cryptographic_parameters,
        cryptographic_usage_mask,
        description,
        digital_signature_algorithm,
        extractable,
        fresh,
        key_format_type,
        key_value_location,
        key_value_present,
        link,
        name,
        never_extractable,
        nist_key_type,
        object_group,
        object_group_member,
        object_type,
        opaque_data_type,
        pkcs_12_friendly_name,
        process_start_date,
        protect_stop_date,
        protection_level,
        protection_period,
        quantum_safe,
        revocation_reason,
        rotate_automatic,
        rotate_date,
        rotate_generation,
        rotate_interval,
        rotate_latest,
        rotate_name,
        rotate_offset,
        sensitive,
        short_unique_identifier,
        state,
        unique_identifier,
        usage_limits,
        x_509_certificate_identifier,
        x_509_certificate_issuer,
        x_509_certificate_subject,
    );
    // Permanent tolerance: the server always adds vendor attributes (a tag used by Locate),
    // so vendor attributes absent from the vector are accepted; expected ones must match.
    if e.vendor_attributes.is_some()
        && e.vendor_attributes != a.vendor_attributes
        && !allowed!(vendor_attributes)
    {
        return mismatch!(vendor_attributes);
    }

    Ok(())
}
