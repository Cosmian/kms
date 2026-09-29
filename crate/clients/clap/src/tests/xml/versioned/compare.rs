//! Version-dispatched payload comparison for KMIP response batch items.
//!
//! Provides `compare_versioned_batch_item` which handles both V14 and V21
//! batch items, delegating to version-specific comparison logic.

use cosmian_kmip::{
    kmip_0::{self, kmip_messages::ResponseMessageBatchItemVersioned},
    kmip_1_4::kmip_operations::Operation as Op14,
    kmip_2_1::{self, kmip_operations::Operation as Op21},
};
use cosmian_kms_client::cosmian_kmip as kms_kmip;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::xml::compare::{compare_attributes, compare_object},
};

/// Compare a single batch item (expected vs actual) for any supported KMIP version.
///
/// Returns an error string prefixed with the batch index for context.
pub(crate) fn compare_versioned_batch_item(
    index: usize,
    exp_item: &ResponseMessageBatchItemVersioned,
    act_item: &ResponseMessageBatchItemVersioned,
) -> KmsCliResult<()> {
    match (exp_item, act_item) {
        (
            ResponseMessageBatchItemVersioned::V21(exp),
            ResponseMessageBatchItemVersioned::V21(act),
        ) => {
            compare_status_and_reason(
                index,
                exp.result_status,
                act.result_status,
                exp.result_reason,
                act.result_reason,
            )?;
            compare_message_presence(
                index,
                exp.result_message.is_some(),
                act.result_message.is_some(),
            )?;

            match (&exp.response_payload, &act.response_payload) {
                (Some(exp_payload), Some(act_payload)) => {
                    compare_payload_v21(exp_payload, act_payload)?;
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] response_payload presence mismatch expected={} actual={}",
                        exp.response_payload.is_some(),
                        act.response_payload.is_some()
                    )));
                }
                (None, None) => {}
            }
        }
        (
            ResponseMessageBatchItemVersioned::V14(exp),
            ResponseMessageBatchItemVersioned::V14(act),
        ) => {
            compare_status_and_reason(
                index,
                exp.result_status,
                act.result_status,
                exp.result_reason,
                act.result_reason,
            )?;
            compare_message_presence(
                index,
                exp.result_message.is_some(),
                act.result_message.is_some(),
            )?;

            match (&exp.response_payload, &act.response_payload) {
                (Some(exp_payload), Some(act_payload)) => {
                    compare_payload_v14(exp_payload, act_payload)?;
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Err(KmsCliError::Default(format!(
                        "batch[{index}] response_payload presence mismatch expected={} actual={}",
                        exp.response_payload.is_some(),
                        act.response_payload.is_some()
                    )));
                }
                (None, None) => {}
            }
        }
        _ => {
            return Err(KmsCliError::Default(format!(
                "batch[{index}] response version mismatch or unsupported combination"
            )));
        }
    }
    Ok(())
}

// ─── Shared helpers ─────────────────────────────────────────────────────────────

fn compare_status_and_reason(
    index: usize,
    exp_status: kmip_0::kmip_types::ResultStatusEnumeration,
    act_status: kmip_0::kmip_types::ResultStatusEnumeration,
    exp_reason: Option<kmip_0::kmip_types::ErrorReason>,
    act_reason: Option<kmip_0::kmip_types::ErrorReason>,
) -> KmsCliResult<()> {
    if exp_status != act_status {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] result_status mismatch expected={exp_status:?} actual={act_status:?}",
        )));
    }
    // For non-success responses, tolerate different result_reason values:
    // different KMIP servers may legitimately return different error reasons.
    if exp_status == kmip_0::kmip_types::ResultStatusEnumeration::Success
        && exp_reason != act_reason
    {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] result_reason mismatch expected={exp_reason:?} actual={act_reason:?}",
        )));
    }
    Ok(())
}

fn compare_message_presence(index: usize, exp_has: bool, act_has: bool) -> KmsCliResult<()> {
    if exp_has != act_has {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] result_message presence mismatch expected={exp_has:?} actual={act_has:?}",
        )));
    }
    Ok(())
}

// ─── Common crypto-response comparison ──────────────────────────────────────────

/// Compare common crypto-response fields shared between all KMIP versions:
/// `EncryptResponse`, `DecryptResponse`, `RNGRetrieveResponse`, `MACResponse`, `QueryResponse`.
macro_rules! compare_common_crypto_responses {
    ($Op:ident,($exp:expr, $act:expr)) => {
        match ($exp, $act) {
            ($Op::EncryptResponse(exp), $Op::EncryptResponse(act)) => {
                if exp.unique_identifier != act.unique_identifier {
                    return Some(Err(KmsCliError::Default(format!(
                        "unique_identifier expected={} actual={}",
                        exp.unique_identifier, act.unique_identifier
                    ))));
                }
                let el = exp.data.as_ref().map_or(0, |v| v.len());
                let al = act.data.as_ref().map_or(0, |v| v.len());
                if el != al {
                    return Some(Err(KmsCliError::Default(format!(
                        "data mismatch expected_len={el} actual_len={al}"
                    ))));
                }
                let el = exp.i_v_counter_nonce.as_ref().map_or(0, |v| v.len());
                let al = act.i_v_counter_nonce.as_ref().map_or(0, |v| v.len());
                if el != al {
                    return Some(Err(KmsCliError::Default(format!(
                        "iv_counter_nonce mismatch expected_len={el} actual_len={al}"
                    ))));
                }
                let el = exp
                    .authenticated_encryption_tag
                    .as_ref()
                    .map_or(0, |v| v.len());
                let al = act
                    .authenticated_encryption_tag
                    .as_ref()
                    .map_or(0, |v| v.len());
                if el != al {
                    return Some(Err(KmsCliError::Default(format!(
                        "authenticated_encryption_tag mismatch expected_len={el} actual_len={al}"
                    ))));
                }
            }
            ($Op::DecryptResponse(exp), $Op::DecryptResponse(act)) => {
                if exp.unique_identifier != act.unique_identifier {
                    return Some(Err(KmsCliError::Default(format!(
                        "unique_identifier expected={} actual={}",
                        exp.unique_identifier, act.unique_identifier
                    ))));
                }
                let el = exp.data.as_ref().map_or(0, |v| v.len());
                let al = act.data.as_ref().map_or(0, |v| v.len());
                if el != al {
                    return Some(Err(KmsCliError::Default(format!(
                        "data mismatch expected_len={el} actual_len={al}"
                    ))));
                }
            }
            ($Op::RNGRetrieveResponse(exp), $Op::RNGRetrieveResponse(act)) => {
                if exp.data.len() != act.data.len() {
                    return Some(Err(KmsCliError::Default(format!(
                        "RNGRetrieveResponse data mismatch expected_len={} actual_len={}",
                        exp.data.len(),
                        act.data.len()
                    ))));
                }
            }
            ($Op::MACResponse(exp), $Op::MACResponse(act)) => {
                if exp.mac_data != act.mac_data {
                    let el = exp.mac_data.as_ref().map_or(0, |v| v.len());
                    let al = act.mac_data.as_ref().map_or(0, |v| v.len());
                    return Some(Err(KmsCliError::Default(format!(
                        "mac_data mismatch expected_len={el} actual_len={al}"
                    ))));
                }
            }
            ($Op::QueryResponse(_exp), $Op::QueryResponse(_act)) => {
                // QueryResponse comparison is lenient: the server may report a different
                // set of supported operations/object types than the reference vector.
                // We only verify that both sides are QueryResponse (discriminant match above).
            }
            _ => {
                return None; // signal: not handled by this macro
            }
        }
        return Some(Ok(()));
    };
}

// ─── KMIP 2.1 payload comparison ────────────────────────────────────────────────

fn compare_payload_v21(expected: &Op21, actual: &Op21) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}"
        )));
    }

    // Try common crypto-response comparisons first
    let handled: Option<KmsCliResult<()>> = (|| {
        compare_common_crypto_responses!(Op21, (expected.clone(), actual.clone()));
    })();
    if let Some(result) = handled {
        return result;
    }

    // Version-specific comparisons
    match (expected.clone(), actual.clone()) {
        (Op21::GetResponse(exp), Op21::GetResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                fn wrapping_encryption_uid(
                    obj: &kmip_2_1::kmip_objects::Object,
                ) -> Option<kmip_2_1::kmip_types::UniqueIdentifier> {
                    use kmip_2_1::kmip_objects::Object::{
                        PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey,
                    };
                    match obj {
                        SymmetricKey(k) => &k.key_block,
                        PrivateKey(k) => &k.key_block,
                        PublicKey(k) => &k.key_block,
                        SecretData(k) => &k.key_block,
                        SplitKey(k) => &k.key_block,
                        _ => return None,
                    }
                    .key_wrapping_data
                    .as_ref()
                    .and_then(|kwd| kwd.encryption_key_information.as_ref())
                    .map(|eki| eki.unique_identifier.clone())
                }

                let act_wrap_uid = wrapping_encryption_uid(&act.object);
                let tolerate = act_wrap_uid
                    .as_ref()
                    .is_some_and(|u| *u == act.unique_identifier);
                if !tolerate {
                    return Err(KmsCliError::Default(format!(
                        "unique_identifier expected={} actual={}",
                        exp.unique_identifier, act.unique_identifier
                    )));
                }
            }
            if exp.object_type != act.object_type {
                return Err(KmsCliError::Default(format!(
                    "object_type expected={:?} actual={:?}",
                    exp.object_type, act.object_type
                )));
            }
            compare_object(&exp.object, &act.object)?;
        }
        (Op21::LocateResponse(exp), Op21::LocateResponse(act)) => {
            if exp.located_items != act.located_items {
                return Err(KmsCliError::Default(format!(
                    "located_items expected={:?} actual={:?}",
                    exp.located_items, act.located_items
                )));
            }
            if exp.unique_identifier != act.unique_identifier {
                compare_uid_list_v21(
                    exp.unique_identifier.as_ref(),
                    act.unique_identifier.as_ref(),
                )?;
            }
        }
        (Op21::GetAttributesResponse(exp), Op21::GetAttributesResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            compare_attributes(&exp.attributes, &act.attributes)?;
        }
        (Op21::GetAttributeListResponse(exp), Op21::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op21::ModifyAttributeResponse(exp), Op21::ModifyAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                let eu = exp
                    .unique_identifier
                    .as_ref()
                    .map_or_else(|| "None".to_string(), std::string::ToString::to_string);
                let au = act
                    .unique_identifier
                    .as_ref()
                    .map_or_else(|| "None".to_string(), std::string::ToString::to_string);
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={eu} actual={au}"
                )));
            }
        }
        (Op21::PKCS11Response(exp), Op21::PKCS11Response(act)) => {
            if exp.pkcs11_function != act.pkcs11_function {
                return Err(KmsCliError::Default(format!(
                    "PKCS11Function expected={:?} actual={:?}",
                    exp.pkcs11_function, act.pkcs11_function
                )));
            }
            if exp.pkcs11_return_code != act.pkcs11_return_code {
                return Err(KmsCliError::Default(format!(
                    "PKCS11ReturnCode expected={:?} actual={:?}",
                    exp.pkcs11_return_code, act.pkcs11_return_code
                )));
            }
            if exp.correlation_value != act.correlation_value {
                let el = exp.correlation_value.as_ref().map_or(0, std::vec::Vec::len);
                let al = act.correlation_value.as_ref().map_or(0, std::vec::Vec::len);
                return Err(KmsCliError::Default(format!(
                    "CorrelationValue mismatch expected_len={el} actual_len={al}"
                )));
            }
        }
        _ => {
            if expected != actual {
                return Err(KmsCliError::Default(format!(
                    "Payload mismatch for {expected}: expected={expected} actual={actual}"
                )));
            }
        }
    }
    Ok(())
}

fn compare_uid_list_v21(
    exp: Option<&Vec<kmip_2_1::kmip_types::UniqueIdentifier>>,
    act: Option<&Vec<kmip_2_1::kmip_types::UniqueIdentifier>>,
) -> KmsCliResult<()> {
    match (exp, act) {
        (Some(e), Some(a)) if e.len() != a.len() => Err(KmsCliError::Default(format!(
            "unique_identifier list mismatch expected_len={} actual_len={}",
            e.len(),
            a.len()
        ))),
        (Some(e), Some(a)) => {
            let first_diff = e
                .iter()
                .map(std::string::ToString::to_string)
                .zip(a.iter().map(std::string::ToString::to_string))
                .enumerate()
                .find(|(_, (l, r))| l != r);
            if let Some((idx, (l, r))) = first_diff {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier[{idx}] expected={l} actual={r}"
                )));
            }
            Err(KmsCliError::Default(
                "unique_identifier lists differ".to_string(),
            ))
        }
        (None, Some(_)) => Err(KmsCliError::Default(
            "unique_identifier expected=None actual=Some".to_string(),
        )),
        (Some(_), None) => Err(KmsCliError::Default(
            "unique_identifier expected=Some actual=None".to_string(),
        )),
        (None, None) => Ok(()),
    }
}

// ─── KMIP 1.4 payload comparison ────────────────────────────────────────────────

fn compare_payload_v14(expected: &Op14, actual: &Op14) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}",
        )));
    }

    // Try common crypto-response comparisons first
    let handled: Option<KmsCliResult<()>> = (|| {
        compare_common_crypto_responses!(Op14, (expected.clone(), actual.clone()));
    })();
    if let Some(result) = handled {
        return result;
    }

    // Version-specific comparisons
    match (expected.clone(), actual.clone()) {
        (Op14::GetResponse(exp), Op14::GetResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                fn wrapping_encryption_uid_14(
                    obj: &kms_kmip::kmip_1_4::kmip_objects::Object,
                ) -> Option<String> {
                    use kms_kmip::kmip_1_4::kmip_objects::Object as Obj14;
                    let kb = match obj {
                        Obj14::SymmetricKey(k) => &k.key_block,
                        Obj14::PrivateKey(k) => &k.key_block,
                        Obj14::PublicKey(k) => &k.key_block,
                        Obj14::SecretData(k) => &k.key_block,
                        Obj14::SplitKey(k) => &k.key_block,
                        _ => return None,
                    };
                    kb.key_wrapping_data
                        .as_ref()
                        .and_then(|kwd| kwd.encryption_key_information.as_ref())
                        .map(|eki| eki.unique_identifier.clone())
                }

                let act_wrap_uid = wrapping_encryption_uid_14(&act.object);
                let tolerate = act_wrap_uid
                    .as_ref()
                    .is_some_and(|u| *u == act.unique_identifier);
                if !tolerate {
                    return Err(KmsCliError::Default(format!(
                        "unique_identifier expected={} actual={}",
                        exp.unique_identifier, act.unique_identifier
                    )));
                }
            }
            if exp.object_type != act.object_type {
                return Err(KmsCliError::Default(format!(
                    "object_type expected={:?} actual={:?}",
                    exp.object_type, act.object_type
                )));
            }
            let exp_obj_21: kms_kmip::kmip_2_1::kmip_objects::Object = exp.object.into();
            let act_obj_21: kms_kmip::kmip_2_1::kmip_objects::Object = act.object.into();
            compare_object(&exp_obj_21, &act_obj_21)?;
        }
        (Op14::LocateResponse(exp), Op14::LocateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                compare_uid_list_v14(
                    exp.unique_identifier.as_ref(),
                    act.unique_identifier.as_ref(),
                )?;
            }
        }
        (Op14::GetAttributesResponse(exp), Op14::GetAttributesResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            let exp_attrs_21: kms_kmip::kmip_2_1::kmip_attributes::Attributes = exp
                .attribute
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<kms_kmip::kmip_2_1::kmip_attributes::Attribute>>()
                .into();
            let act_attrs_21: kms_kmip::kmip_2_1::kmip_attributes::Attributes = act
                .attribute
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<kms_kmip::kmip_2_1::kmip_attributes::Attribute>>()
                .into();
            compare_attributes(&exp_attrs_21, &act_attrs_21)?;
        }
        (Op14::GetAttributeListResponse(exp), Op14::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::AddAttributeResponse(exp), Op14::AddAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "AddAttributeResponse unique_identifier mismatch expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::DeleteAttributeResponse(exp), Op14::DeleteAttributeResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "DeleteAttributeResponse mismatch\n  expected uid={} attr={:?}\n  actual   uid={} attr={:?}",
                    exp.unique_identifier, exp.attribute, act.unique_identifier, act.attribute
                )));
            }
        }
        (Op14::ModifyAttributeResponse(exp), Op14::ModifyAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "ModifyAttributeResponse unique_identifier mismatch expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        _ => {
            if expected != actual {
                return Err(KmsCliError::Default(format!(
                    "Payload mismatch for expected={expected} actual={actual}",
                )));
            }
        }
    }
    Ok(())
}

fn compare_uid_list_v14(exp: Option<&Vec<String>>, act: Option<&Vec<String>>) -> KmsCliResult<()> {
    match (exp, act) {
        (Some(e), Some(a)) if e.len() != a.len() => Err(KmsCliError::Default(format!(
            "unique_identifier list mismatch expected_len={} actual_len={}",
            e.len(),
            a.len()
        ))),
        (Some(e), Some(a)) => {
            let first_diff = e
                .iter()
                .zip(a.iter())
                .enumerate()
                .find(|(_, (l, r))| l != r);
            if let Some((idx, (l, r))) = first_diff {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier[{idx}] expected={l} actual={r}"
                )));
            }
            Err(KmsCliError::Default(
                "unique_identifier lists differ".to_string(),
            ))
        }
        (None, Some(_)) => Err(KmsCliError::Default(
            "unique_identifier expected=None actual=Some".to_string(),
        )),
        (Some(_), None) => Err(KmsCliError::Default(
            "unique_identifier expected=Some actual=None".to_string(),
        )),
        (None, None) => Ok(()),
    }
}
