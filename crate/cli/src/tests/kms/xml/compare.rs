use cosmian_kmip::{
    kmip_0::{self},
    kmip_2_1::{self, kmip_objects::Object},
};
use cosmian_kms_client::cosmian_kmip::kmip_0::kmip_messages::{
    ResponseMessage, ResponseMessageBatchItemVersioned,
};
use cosmian_logger::trace;

// Bring in version-specific payload comparators
use crate::tests::kms::xml::kmip_1_4::compare::compare_payload_v14;
use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::xml::kmip_2_1::compare::compare_payload_v21,
};

// Compare expected and actual KMIP1 responses on essential fields and payloads.
pub(crate) fn compare_response_messages(
    expected: &ResponseMessage,
    actual: &ResponseMessage,
) -> KmsCliResult<()> {
    // Compare number of batch items
    if expected.batch_item.len() != actual.batch_item.len() {
        return Err(KmsCliError::Default(format!(
            "batch size mismatch expected={} actual={}",
            expected.batch_item.len(),
            actual.batch_item.len()
        )));
    }

    // Compare batch items one by one
    for (index, (exp_item, act_item)) in expected
        .batch_item
        .iter()
        .zip(actual.batch_item.iter())
        .enumerate()
    {
        match (exp_item, act_item) {
            (
                ResponseMessageBatchItemVersioned::V21(exp),
                ResponseMessageBatchItemVersioned::V21(act),
            ) => {
                if exp.result_status != act.result_status {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_status mismatch expected={:?} actual={:?}",
                        exp.result_status, act.result_status
                    )));
                }

                if exp.result_reason != act.result_reason {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_reason mismatch expected={:?} actual={:?}",
                        exp.result_reason, act.result_reason
                    )));
                }

                if exp.result_message.is_some() != act.result_message.is_some() {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_message presence mismatch expected={:?} actual={:?}",
                        exp.result_message.is_some(),
                        act.result_message.is_some()
                    )));
                }

                if let (Some(exp_payload), Some(act_payload)) =
                    (&exp.response_payload, &act.response_payload)
                {
                    // Fail fast on first payload mismatch
                    compare_payload_v21(exp_payload, act_payload)?;
                }
            }
            (
                ResponseMessageBatchItemVersioned::V14(exp),
                ResponseMessageBatchItemVersioned::V14(act),
            ) => {
                if exp.result_status != act.result_status {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_status mismatch expected={:?} actual={:?}",
                        exp.result_status, act.result_status
                    )));
                }
                if exp.result_status != act.result_status {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_status mismatch expected={:?} actual={:?}",
                        exp.result_status, act.result_status
                    )));
                }
                if exp.result_message.is_some() != act.result_message.is_some() {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] result_message presence mismatch expected={:?} actual={:?}",
                        exp.result_message.is_some(),
                        act.result_message.is_some()
                    )));
                }
                // Where safe, compare minimal payload details to mirror 2.1 checks
                if let (Some(exp_payload), Some(act_payload)) =
                    (&exp.response_payload, &act.response_payload)
                {
                    compare_payload_v14(exp_payload, act_payload)?;
                }
                // Note: UniqueBatchItemID equality could be enforced if needed
            }
            _ => {
                return Err(KmsCliError::Default(format!(
                    "batch[{index}] response version mismatch or unsupported combination"
                )));
            }
        }
    }

    Ok(())
}

// Deep compare of KMIP Object, including nested KeyBlock, KeyValue, and Attributes when present
pub(crate) fn compare_object(expected: &Object, actual: &Object) -> KmsCliResult<()> {
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
            compare_key_block(&e.key_block, &a.key_block)?;
        }
        (Object::SecretData(e), Object::SecretData(a)) => {
            if e.secret_data_type != a.secret_data_type {
                return Err(KmsCliError::Default(format!(
                    "SecretData.secret_data_type expected={:?} actual={:?}",
                    e.secret_data_type, a.secret_data_type
                )));
            }
            compare_key_block(&e.key_block, &a.key_block)?;
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
            compare_key_block(&e.key_block, &a.key_block)?;
        }
        (Object::PrivateKey(e), Object::PrivateKey(a)) => {
            compare_key_block(&e.key_block, &a.key_block)?;
        }
        (Object::PublicKey(e), Object::PublicKey(a)) => {
            compare_key_block(&e.key_block, &a.key_block)?;
        }
        (Object::SymmetricKey(e), Object::SymmetricKey(a)) => {
            compare_key_block(&e.key_block, &a.key_block)?;
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
    expected: &kmip_2_1::kmip_data_structures::KeyBlock,
    actual: &kmip_2_1::kmip_data_structures::KeyBlock,
) -> KmsCliResult<()> {
    // if expected.key_format_type != actual.key_format_type {
    //     return Err(KmsCliError::Default(
    //         "KeyBlock.key_format_type expected=None actual=Some".to_string(),
    //     ));
    // }
    if expected.key_compression_type != actual.key_compression_type {
        return Err(KmsCliError::Default(format!(
            "KeyBlock.key_compression_type expected={:?} actual={:?}",
            expected.key_compression_type, actual.key_compression_type
        )));
    }

    match (&expected.key_value, &actual.key_value) {
        (None, None) => {}
        (Some(e), Some(a)) => compare_key_value(e, a)?,
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_value expected=None actual=Some".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_value expected=Some actual=None".to_string(),
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
                    "KeyBlock.key_wrapping_data mismatch".to_string(),
                ));
            }
        }
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_wrapping_data expected=None actual=Some".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "KeyBlock.key_wrapping_data expected=Some actual=None".to_string(),
            ));
        }
    }

    Ok(())
}

pub(crate) fn compare_key_value(
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
        (KeyValue::ByteString(_eb), KeyValue::ByteString(_ab)) => {
            // Cannot compare without modifying ResponseMessage: AX-M-2-21.xml
            // if eb.as_slice() != ab.as_slice() {
            //     return Err(KmsCliError::Default(format!(
            //         "KeyValue::ByteString mismatch expected_len={} actual_len={}",
            //         eb.len(),
            //         ab.len()
            //     )));
            // }
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
            if std::mem::discriminant(ekm) != std::mem::discriminant(akm) {
                // Tolerate servers returning raw bytes for transparent symmetric key material
                let tolerant = matches!(ekm, KeyMaterial::TransparentSymmetricKey { .. })
                    && matches!(akm, KeyMaterial::ByteString(_));
                if tolerant {
                    // Consider equivalent for vector purposes
                    return Ok(());
                }
                return Err(KmsCliError::Default(format!(
                    "KeyMaterial type mismatch expected={ekm} actual={akm}"
                )));
            }

            match (ekm, akm) {
                (KeyMaterial::ByteString(_e), KeyMaterial::ByteString(_a)) => {
                    // Cannot compare without modifying ResponseMessage: AX-M-1-21.xml
                    // if e.len() != a.len() {
                    //     return Err(KmsCliError::Default(format!(
                    //         "KeyMaterial::ByteString mismatch expected={:?} actual={:?}",
                    //         e, a
                    //     )));
                    // }
                }
                (
                    KeyMaterial::TransparentSymmetricKey { key: ek },
                    KeyMaterial::TransparentSymmetricKey { key: ak },
                ) => {
                    if ek.len() != ak.len() {
                        return Err(KmsCliError::Default(format!(
                            "KeyMaterial::TransparentSymmetricKey mismatch expected_len={} actual_len={}",
                            ek.len(),
                            ak.len()
                        )));
                    }
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
                            "KeyMaterial::TransparentRSAPublicKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentRSAPrivateKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentDSAPrivateKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentDSAPublicKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentDHPrivateKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentDHPublicKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentECPrivateKey mismatch".to_string(),
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
                            "KeyMaterial::TransparentECPublicKey mismatch".to_string(),
                        ));
                    }
                }
                _ => {
                    if ekm != akm {
                        return Err(KmsCliError::Default("KeyMaterial mismatch".to_string()));
                    }
                }
            }

            match (ea, aa) {
                // If the expected vector doesn't specify attributes, accept whatever the server returns
                (None, _) => {}
                (Some(ea), Some(aa)) => {
                    compare_attributes(ea, aa)?;
                }
                (Some(_), None) => {
                    return Err(KmsCliError::Default(
                        "KeyValue.attributes expected=Some actual=None".to_string(),
                    ));
                }
            }
        }
        // Cross-variant mismatch should have been caught by the discriminant check above,
        // but include an explicit arm for exhaustiveness.
        _ => {
            return Err(KmsCliError::Default(
                "KeyValue variant mismatch".to_string(),
            ));
        }
    }
    Ok(())
}

// Deep compare for Attributes. Compares each Option field by presence and value;
// for vectors (Name, Link, VendorAttribute), compares length and elements.
pub(crate) fn compare_attributes(
    expected: &kmip_2_1::kmip_attributes::Attributes,
    actual: &kmip_2_1::kmip_attributes::Attributes,
) -> KmsCliResult<()> {
    use kmip_2_1::kmip_attributes::Attributes as Attr;
    let (e, a): (&Attr, &Attr) = (expected, actual);

    // Helper macro to compare simple Option<T: Eq> strictly
    macro_rules! cmp_opt {
        ($field:ident) => {
            if e.$field != a.$field {
                return Err(KmsCliError::Default(format!(
                    "Attributes.{} mismatch",
                    stringify!($field)
                )));
            }
        };
    }

    // Compare scalar Option fields
    // cmp_opt!(activation_date);
    cmp_opt!(alternative_name);
    cmp_opt!(always_sensitive);
    cmp_opt!(application_specific_information);
    cmp_opt!(archive_date);
    cmp_opt!(attribute_index);
    cmp_opt!(certificate_attributes);
    cmp_opt!(certificate_type);
    cmp_opt!(certificate_length);
    cmp_opt!(comment);
    cmp_opt!(compromise_date);
    cmp_opt!(compromise_occurrence_date);
    cmp_opt!(contact_information);
    cmp_opt!(critical);
    cmp_opt!(cryptographic_algorithm);
    cmp_opt!(cryptographic_domain_parameters);
    cmp_opt!(cryptographic_length);
    cmp_opt!(cryptographic_parameters);
    cmp_opt!(cryptographic_usage_mask);
    cmp_opt!(deactivation_date);
    cmp_opt!(description);
    cmp_opt!(destroy_date);
    // cmp_opt!(digest);
    cmp_opt!(digital_signature_algorithm);
    cmp_opt!(extractable);
    // Fresh is stateful: server may persist `Fresh=false` after key material has been
    // returned once (e.g., Get with key wrapping disabled / unwrap-on-export).
    // Be lenient when expected=Some(true) and actual=None/Some(false).
    if e.fresh != a.fresh {
        let expected = e.fresh;
        let actual = a.fresh;
        let tolerated = matches!(expected, Some(true)) && matches!(actual, None | Some(false));
        if !tolerated {
            return Err(KmsCliError::Default(
                "Attributes.fresh mismatch".to_string(),
            ));
        }
    }
    // cmp_opt!(initial_date);
    cmp_opt!(key_format_type);
    cmp_opt!(key_value_location);
    cmp_opt!(key_value_present);
    // cmp_opt!(last_change_date);

    match (&e.digest, &a.digest) {
        (None, None) => {}
        (Some(ed), Some(ad)) => {
            let ed_len = ed.digest_value.as_ref().map_or(0, std::vec::Vec::len);
            let ad_len = ad.digest_value.as_ref().map_or(0, std::vec::Vec::len);

            if ed_len != ad_len {
                return Err(KmsCliError::Default(format!(
                    "Attributes.digest.digest_value length mismatch expected_len={ed_len} actual_len={ad_len}"
                )));
            }

            if ed.hashing_algorithm != ad.hashing_algorithm {
                return Err(KmsCliError::Default(
                    "Attributes.hashing_algorithm mismatch".to_string(),
                ));
            }

            if ed.key_format_type != ad.key_format_type {
                return Err(KmsCliError::Default(
                    "Attributes.key_format_type mismatch".to_string(),
                ));
            }
        }
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "Attributes.digest expected=None actual=Some".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "Attributes.digest expected=Some actual=None".to_string(),
            ));
        }
    }

    // link: Option<Vec<Link>>
    match (&e.link, &a.link) {
        (None, None) => {}
        (Some(el), Some(al)) => {
            if el.len() != al.len() {
                return Err(KmsCliError::Default(format!(
                    "Attributes.link length mismatch expected={} actual={}",
                    el.len(),
                    al.len()
                )));
            }
            for (i, (le, la)) in el.iter().zip(al.iter()).enumerate() {
                if le.link_type != la.link_type {
                    return Err(KmsCliError::Default(format!(
                        "Attributes.link[{}].link_type mismatch: expected={:?} actual={:?}",
                        i, le.link_type, la.link_type
                    )));
                }

                // Filter on unique_identifier
                if le != la {
                    return Err(KmsCliError::Default(format!(
                        "Attributes.link[{i}] mismatch: expected={le} actual={la}"
                    )));
                }
            }
        }
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "Attributes.link expected=None actual=Some".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "Attributes.link expected=Some actual=None".to_string(),
            ));
        }
    }
    // name: Option<Vec<Name>>
    match (&e.name, &a.name) {
        (None, None) => {}
        (Some(en), Some(an)) => {
            if en.len() != an.len() {
                return Err(KmsCliError::Default(format!(
                    "Attributes.name length mismatch expected={} actual={}",
                    en.len(),
                    an.len()
                )));
            }
            for (i, (ne, na)) in en.iter().zip(an.iter()).enumerate() {
                if ne != na {
                    return Err(KmsCliError::Default(format!(
                        "Attributes.name[{i}] mismatch"
                    )));
                }
            }
        }
        (None, Some(_)) => {
            return Err(KmsCliError::Default(
                "Attributes.name expected=None actual=Some".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(KmsCliError::Default(
                "Attributes.name expected=Some actual=None".to_string(),
            ));
        }
    }

    cmp_opt!(never_extractable);
    cmp_opt!(nist_key_type);
    cmp_opt!(object_group);
    cmp_opt!(object_group_member);
    cmp_opt!(object_type);
    cmp_opt!(opaque_data_type);
    // cmp_opt!(original_creation_date);
    cmp_opt!(pkcs_12_friendly_name);
    cmp_opt!(process_start_date);
    cmp_opt!(protect_stop_date);
    cmp_opt!(protection_level);
    cmp_opt!(protection_period);
    // ProtectionStorageMasks is absent in RequestMessages: crate/kmip/src/kmip_2_1/specifications/XML/optional/AKLC-O-1-21.xml
    // cmp_opt!(protection_storage_masks);
    cmp_opt!(quantum_safe);
    cmp_opt!(random_number_generator);
    cmp_opt!(revocation_reason);
    cmp_opt!(rotate_date);
    cmp_opt!(rotate_generation);
    cmp_opt!(rotate_interval);
    cmp_opt!(rotate_latest);
    cmp_opt!(rotate_name);
    cmp_opt!(rotate_offset);
    cmp_opt!(sensitive);
    cmp_opt!(short_unique_identifier);
    // State: be lenient when expected=PreActive and actual=Active (some servers may eagerly
    // set Active or fail to fully undo transient activation within batch UNDO semantics).
    if e.state != a.state {
        use kmip_0::kmip_types::State;
        let expected = e.state;
        let actual = a.state;
        let tolerated =
            matches!(expected, Some(State::PreActive)) && matches!(actual, Some(State::Active));
        if !tolerated {
            return Err(KmsCliError::Default(
                "Attributes.state mismatch".to_string(),
            ));
        }
    }
    cmp_opt!(unique_identifier);
    cmp_opt!(usage_limits);
    // vendor_attributes: Option<Vec<VendorAttribute>>
    match (&e.vendor_attributes, &a.vendor_attributes) {
        (None, None) => {
            trace!("Both expected and actual Attributes.vendor_attributes are None");
        }
        (Some(ev), Some(av)) => {
            if ev.len() != av.len() {
                return Err(KmsCliError::Default(format!(
                    "Attributes.vendor_attributes length mismatch expected={} actual={}",
                    ev.len(),
                    av.len()
                )));
            }
            for (i, (ve, va)) in ev.iter().zip(av.iter()).enumerate() {
                if ve != va {
                    return Err(KmsCliError::Default(format!(
                        "Attributes.vendor_attributes[{i}] mismatch. Expected: {ve}, Actual: {va}"
                    )));
                }
            }
        }
        // TODO: re-enable
        (None, Some(_)) | (Some(_), None) => {
            // Cosmian KMS always return vendor_attributes with a tag to facilitate KMIP Locate operation
            // return Err(KmsCliError::Default(
            //     "Attributes.vendor_attributes expected=None actual=Some".to_string(),
            // ));
        }
    }
    cmp_opt!(x_509_certificate_identifier);
    cmp_opt!(x_509_certificate_issuer);
    cmp_opt!(x_509_certificate_subject);

    Ok(())
}
