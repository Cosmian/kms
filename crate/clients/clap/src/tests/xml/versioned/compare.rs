//! Version-dispatched payload comparison for KMIP response batch items.
//!
//! Provides `compare_versioned_batch_item` which handles both V14 and V21
//! batch items, delegating to version-specific comparison logic.

use cosmian_kmip::{
    kmip_0::{self, kmip_messages::ResponseMessageBatchItemVersioned},
    kmip_1_4::kmip_operations::Operation as Op14,
    kmip_2_1::{self, kmip_operations::Operation as Op21, kmip_types::AttributeReference},
};
use cosmian_kms_client::cosmian_kmip as kms_kmip;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::xml::{
        compare::{compare_attributes, compare_object},
        deviations::{
            Ctx, KEY_FORMAT_TYPE_1X, UNSUPPORTED_OBJECT_TYPES, UNSUPPORTED_OPERATIONS,
            is_unimplemented_attribute,
        },
        request::is_ticket_value_placeholder,
    },
};

/// Compare a single batch item (expected vs actual) for any supported KMIP version.
///
/// Returns an error string prefixed with the batch index for context.
pub(crate) fn compare_versioned_batch_item(
    ctx: &Ctx,
    exp_item: &ResponseMessageBatchItemVersioned,
    act_item: &ResponseMessageBatchItemVersioned,
) -> KmsCliResult<()> {
    let index = ctx.batch;
    match (exp_item, act_item) {
        (
            ResponseMessageBatchItemVersioned::V21(exp),
            ResponseMessageBatchItemVersioned::V21(act),
        ) => {
            compare_status_and_reason(
                ctx,
                exp.result_status,
                act.result_status,
                exp.result_reason.as_ref(),
                act.result_reason.as_ref(),
            )?;
            compare_message_presence(
                index,
                exp.result_message.is_some(),
                act.result_message.is_some(),
            )?;
            compare_item_echo(
                ctx,
                exp.operation.as_ref(),
                act.operation.as_ref(),
                exp.unique_batch_item_id.as_ref(),
                act.unique_batch_item_id.as_ref(),
            )?;

            match (&exp.response_payload, &act.response_payload) {
                (Some(exp_payload), Some(act_payload)) => {
                    compare_payload_v21(ctx, exp_payload, act_payload)?;
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
                ctx,
                exp.result_status,
                act.result_status,
                exp.result_reason.as_ref(),
                act.result_reason.as_ref(),
            )?;
            compare_message_presence(
                index,
                exp.result_message.is_some(),
                act.result_message.is_some(),
            )?;
            compare_item_echo(
                ctx,
                exp.operation.as_ref(),
                act.operation.as_ref(),
                exp.unique_batch_item_id.as_ref(),
                act.unique_batch_item_id.as_ref(),
            )?;

            match (&exp.response_payload, &act.response_payload) {
                (Some(exp_payload), Some(act_payload)) => {
                    compare_payload_v14(ctx, exp_payload, act_payload)?;
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

fn compare_status_and_reason<R>(
    ctx: &Ctx,
    exp_status: kmip_0::kmip_types::ResultStatusEnumeration,
    act_status: kmip_0::kmip_types::ResultStatusEnumeration,
    exp_reason: Option<&R>,
    act_reason: Option<&R>,
) -> KmsCliResult<()>
where
    R: std::fmt::Debug + PartialEq + Clone + Into<kmip_0::kmip_types::ErrorReason>,
{
    let index = ctx.batch;
    if exp_status != act_status {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] result_status mismatch expected={exp_status:?} actual={act_status:?}",
        )));
    }
    if exp_status == kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed
        && exp_reason.is_none()
    {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] expected failed response omits ResultReason",
        )));
    }
    let accepted = || match (exp_reason, act_reason) {
        (Some(exp), Some(act)) => ctx.allows_reason(exp.clone().into(), act.clone().into()),
        _ => false,
    };
    if exp_reason != act_reason && !accepted() {
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

/// Operation and Unique Batch Item ID echoed in a response batch item.
fn compare_item_echo<O: std::fmt::Debug + PartialEq>(
    ctx: &Ctx,
    exp_op: Option<&O>,
    act_op: Option<&O>,
    exp_id: Option<&Vec<u8>>,
    act_id: Option<&Vec<u8>>,
) -> KmsCliResult<()> {
    let index = ctx.batch;
    if exp_op != act_op && !ctx.allows("operation") {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] operation mismatch expected={exp_op:?} actual={act_op:?}",
        )));
    }
    if exp_id != act_id && !ctx.allows("unique_batch_item_id") {
        return Err(KmsCliError::Default(format!(
            "batch[{index}] unique_batch_item_id mismatch expected={exp_id:?} actual={act_id:?}",
        )));
    }
    Ok(())
}

// ─── Common crypto-response comparison ──────────────────────────────────────────

/// Compare common crypto-response fields shared between all KMIP versions:
/// `EncryptResponse`, `DecryptResponse`, `RNGRetrieveResponse`, `MACResponse`, `QueryResponse`.
macro_rules! compare_common_crypto_responses {
    ($ctx:expr, $Op:ident,($exp:expr, $act:expr)) => {
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
                // Placeholders were replaced by the actual IV beforehand: a literal must match.
                if exp.i_v_counter_nonce != act.i_v_counter_nonce && !$ctx.allows("encrypt.iv") {
                    return Some(Err(KmsCliError::Default(
                        "iv_counter_nonce bytes mismatch".to_owned(),
                    )));
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
                // Without a server-generated IV the output is deterministic for a known key: the
                // AEAD and multi-part vectors that Register their keys are checked byte for byte;
                // under a key this server generated (Create) the vector's literal cannot match.
                if act.i_v_counter_nonce.is_none()
                    && (exp.authenticated_encryption_tag.is_some()
                        || exp.correlation_value.is_some())
                    && !$ctx
                        .for_object(&act.unique_identifier.to_string())
                        .object_generated
                {
                    if exp.data != act.data {
                        return Some(Err(KmsCliError::Default(
                            "data mismatch (deterministic encryption)".to_owned(),
                        )));
                    }
                    if exp.authenticated_encryption_tag != act.authenticated_encryption_tag {
                        return Some(Err(KmsCliError::Default(
                            "authenticated_encryption_tag mismatch (deterministic encryption)"
                                .to_owned(),
                        )));
                    }
                }
                if exp.correlation_value != act.correlation_value {
                    return Some(Err(KmsCliError::Default(format!(
                        "correlation_value mismatch expected_present={} actual_present={}",
                        exp.correlation_value.is_some(),
                        act.correlation_value.is_some()
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
                if exp.data != act.data && !$ctx.allows("decrypt.data") {
                    return Some(Err(KmsCliError::Default(
                        "data mismatch (decrypted bytes differ)".to_owned(),
                    )));
                }
                if exp.correlation_value != act.correlation_value {
                    return Some(Err(KmsCliError::Default(format!(
                        "correlation_value mismatch expected_present={} actual_present={}",
                        exp.correlation_value.is_some(),
                        act.correlation_value.is_some()
                    ))));
                }
            }
            ($Op::SignResponse(exp), $Op::SignResponse(act)) => {
                if exp.signature_data != act.signature_data && !$ctx.allows("sign.signature_data") {
                    return Some(Err(KmsCliError::Default(
                        "signature_data mismatch".to_owned(),
                    )));
                }
                let mut exp = exp;
                exp.signature_data.clone_from(&act.signature_data);
                if exp != act {
                    return Some(Err(KmsCliError::Default(format!(
                        "SignResponse mismatch expected={exp} actual={act}"
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
                if exp.correlation_value != act.correlation_value {
                    return Some(Err(KmsCliError::Default(format!(
                        "correlation_value mismatch expected_present={} actual_present={}",
                        exp.correlation_value.is_some(),
                        act.correlation_value.is_some()
                    ))));
                }
            }
            ($Op::QueryResponse(exp), $Op::QueryResponse(act)) => {
                // Every operation and object type of the vector must be reported; the server
                // may support more. Server identity fields are server-specific: not compared.
                let missing_ops: Vec<_> = exp
                    .operation
                    .iter()
                    .flatten()
                    .filter(|o| !act.operation.iter().flatten().any(|a| a == *o))
                    .filter(|o| !UNSUPPORTED_OPERATIONS.contains(&format!("{o:?}").as_str()))
                    .collect();
                if !missing_ops.is_empty() && !$ctx.allows("query.operation") {
                    return Some(Err(KmsCliError::Default(format!(
                        "QueryResponse operations missing: {missing_ops:?}"
                    ))));
                }
                let missing_types: Vec<_> = exp
                    .object_type
                    .iter()
                    .flatten()
                    .filter(|o| !act.object_type.iter().flatten().any(|a| a == *o))
                    .filter(|o| !UNSUPPORTED_OBJECT_TYPES.contains(&format!("{o:?}").as_str()))
                    .collect();
                if !missing_types.is_empty() && !$ctx.allows("query.object_type") {
                    return Some(Err(KmsCliError::Default(format!(
                        "QueryResponse object types missing: {missing_types:?}"
                    ))));
                }
            }
            _ => {
                return None; // signal: not handled by this macro
            }
        }
        return Some(Ok(()));
    };
}

// ─── KMIP 2.1 payload comparison ────────────────────────────────────────────────

fn compare_payload_v21(ctx: &Ctx, expected: &Op21, actual: &Op21) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}"
        )));
    }

    // Try common crypto-response comparisons first
    let handled: Option<KmsCliResult<()>> = (|| {
        compare_common_crypto_responses!(ctx, Op21, (expected.clone(), actual.clone()));
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
            let obj_ctx = ctx.for_object(&act.unique_identifier.to_string());
            compare_object(&obj_ctx, &exp.object, &act.object)?;
        }
        (Op21::LocateResponse(exp), Op21::LocateResponse(act)) => {
            if exp.located_items != act.located_items && !ctx.allows("locate.items") {
                return Err(KmsCliError::Default(format!(
                    "located_items expected={:?} actual={:?}",
                    exp.located_items, act.located_items
                )));
            }
            if exp.unique_identifier != act.unique_identifier && !ctx.allows("locate.items") {
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
            let obj_ctx = ctx.for_object(&act.unique_identifier.to_string());
            compare_attributes(&obj_ctx, &exp.attributes, &act.attributes)?;
        }
        (Op21::ExportResponse(exp), Op21::ExportResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.object_type != act.object_type {
                return Err(KmsCliError::Default(format!(
                    "object_type expected={:?} actual={:?}",
                    exp.object_type, act.object_type
                )));
            }
            let obj_ctx = ctx.for_object(&act.unique_identifier.to_string());
            compare_attributes(&obj_ctx, &exp.attributes, &act.attributes)?;
            compare_object(&obj_ctx, &exp.object, &act.object)?;
        }
        (Op21::GetAttributeListResponse(exp), Op21::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if let Some(exp_refs) = &exp.attribute_references {
                let act_refs = act.attribute_references.as_deref().unwrap_or_default();
                // Systematic deviation: see `UNIMPLEMENTED_ATTRIBUTES`.
                let exp_refs: Vec<_> = exp_refs
                    .iter()
                    .filter(|r| {
                        act_refs.contains(r)
                            || !matches!(r, AttributeReference::Standard(tag)
                                if is_unimplemented_attribute(&format!("{tag:?}")))
                    })
                    .cloned()
                    .collect();
                if !same_set(&exp_refs, act_refs) && !ctx.allows("get_attribute_list.names") {
                    return Err(KmsCliError::Default(format!(
                        "attribute_references expected={exp_refs:?} actual={act_refs:?}"
                    )));
                }
            }
        }
        (Op21::ModifyAttributeResponse(exp), Op21::ModifyAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                let eu = exp
                    .unique_identifier
                    .as_ref()
                    .map_or_else(|| "None".to_owned(), std::string::ToString::to_string);
                let au = act
                    .unique_identifier
                    .as_ref()
                    .map_or_else(|| "None".to_owned(), std::string::ToString::to_string);
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={eu} actual={au}"
                )));
            }
        }
        (Op21::LoginResponse(exp), Op21::LoginResponse(act)) => {
            // The Ticket Value is random: `$TICKET_VALUE` only requires a value, any literal
            // must match exactly.
            let (exp, act) = (&exp.ticket, &act.ticket);
            let value_ok = if is_ticket_value_placeholder(&exp.ticket_value) {
                !act.ticket_value.is_empty()
            } else {
                exp.ticket_value == act.ticket_value
            };
            if exp.ticket_type != act.ticket_type || !value_ok {
                return Err(KmsCliError::Default(format!(
                    "Ticket mismatch: expected type={:?} value_len={} actual type={:?} \
                     value_len={}",
                    exp.ticket_type,
                    exp.ticket_value.len(),
                    act.ticket_type,
                    act.ticket_value.len()
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
                "unique_identifier lists differ".to_owned(),
            ))
        }
        (None, Some(_)) => Err(KmsCliError::Default(
            "unique_identifier expected=None actual=Some".to_owned(),
        )),
        (Some(_), None) => Err(KmsCliError::Default(
            "unique_identifier expected=Some actual=None".to_owned(),
        )),
        (None, None) => Ok(()),
    }
}

// ─── KMIP 1.4 payload comparison ────────────────────────────────────────────────

fn compare_payload_v14(ctx: &Ctx, expected: &Op14, actual: &Op14) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}",
        )));
    }

    // Try common crypto-response comparisons first
    let handled: Option<KmsCliResult<()>> = (|| {
        compare_common_crypto_responses!(ctx, Op14, (expected.clone(), actual.clone()));
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
            compare_object(
                &ctx.for_object(&act.unique_identifier),
                &exp_obj_21,
                &act_obj_21,
            )?;
        }
        (Op14::LocateResponse(exp), Op14::LocateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier && !ctx.allows("locate.items") {
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
            compare_attributes(
                &ctx.for_object(&act.unique_identifier),
                &exp_attrs_21,
                &act_attrs_21,
            )?;
        }
        (Op14::GetAttributeListResponse(exp), Op14::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            // 1.0 vectors were extracted from HTML with runs of spaces inside names.
            let normalize = |n: &String| n.split_whitespace().collect::<Vec<_>>().join(" ");
            let exp_names: Vec<String> = exp.attribute_names.iter().map(normalize).collect();
            let mut act_names: Vec<String> = act.attribute_names.iter().map(normalize).collect();
            // Systematic deviations: see `UNIMPLEMENTED_ATTRIBUTES` and `KEY_FORMAT_TYPE_1X`;
            // the server sets Random Number Generator on objects it generates (KMIP 1.3+ 3.44).
            let generated = ctx.for_object(&act.unique_identifier).object_generated;
            act_names.retain(|n| {
                exp_names.contains(n)
                    || (n != KEY_FORMAT_TYPE_1X && !(generated && n == "Random Number Generator"))
            });
            let exp_names: Vec<String> = exp_names
                .into_iter()
                .filter(|n| act_names.contains(n) || !is_unimplemented_attribute(n))
                .collect();
            if !same_set(&exp_names, &act_names) && !ctx.allows("get_attribute_list.names") {
                return Err(KmsCliError::Default(format!(
                    "attribute_names expected={exp_names:?} actual={act_names:?}"
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
            if exp.attribute != act.attribute && !ctx.allows("attribute_response.attribute") {
                return Err(KmsCliError::Default(format!(
                    "AddAttributeResponse attribute expected={:?} actual={:?}",
                    exp.attribute, act.attribute
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
            if exp.attribute != act.attribute && !ctx.allows("attribute_response.attribute") {
                return Err(KmsCliError::Default(format!(
                    "ModifyAttributeResponse attribute expected={:?} actual={:?}",
                    exp.attribute, act.attribute
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

/// Order-insensitive equality of two lists.
fn same_set<T: PartialEq>(exp: &[T], act: &[T]) -> bool {
    exp.iter().all(|e| act.contains(e)) && act.iter().all(|a| exp.contains(a))
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
                "unique_identifier lists differ".to_owned(),
            ))
        }
        (None, Some(_)) => Err(KmsCliError::Default(
            "unique_identifier expected=None actual=Some".to_owned(),
        )),
        (Some(_), None) => Err(KmsCliError::Default(
            "unique_identifier expected=Some actual=None".to_owned(),
        )),
        (None, None) => Ok(()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn status_and_reason(
        position: (&str, usize),
        exp_reason: Option<&kmip_0::kmip_types::ErrorReason>,
        act_reason: Option<&kmip_0::kmip_types::ErrorReason>,
    ) -> KmsCliResult<()> {
        let generated_uids = std::collections::HashSet::new();
        let ctx = Ctx {
            vector: position.0,
            request: position.1,
            batch: 0,
            generated_uids: &generated_uids,
            object_generated: false,
        };
        compare_status_and_reason(
            &ctx,
            kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed,
            kmip_0::kmip_types::ResultStatusEnumeration::OperationFailed,
            exp_reason,
            act_reason,
        )
    }

    #[test]
    fn failed_response_must_specify_reason() {
        let result = status_and_reason(("test", 0), None, None);

        assert!(result.is_err());
    }

    #[test]
    fn failure_result_reason_must_match() {
        let expected_reason = kmip_0::kmip_types::ErrorReason::Invalid_Field;
        let actual_reason = kmip_0::kmip_types::ErrorReason::General_Failure;
        let result = status_and_reason(("test", 0), Some(&expected_reason), Some(&actual_reason));

        assert!(result.is_err());
    }

    /// A `REASON_DEVIATIONS` entry accepts only its exact pair at its listed positions.
    #[test]
    fn reason_deviation_is_exact() -> KmsCliResult<()> {
        use kmip_0::kmip_types::ErrorReason;
        let denied = ErrorReason::Permission_Denied;
        let wkls = ErrorReason::Wrong_Key_Lifecycle_State;
        let listed = ("CS-BC-M-14-20", 1);
        status_and_reason(listed, Some(&denied), Some(&wkls))?;
        let other_actual = ErrorReason::General_Failure;
        assert!(status_and_reason(listed, Some(&denied), Some(&other_actual)).is_err());
        assert!(status_and_reason(listed, Some(&wkls), Some(&denied)).is_err());
        assert!(status_and_reason(("CS-BC-M-14-21", 1), Some(&denied), Some(&wkls)).is_err());
        assert!(status_and_reason(("CS-BC-M-14-20", 3), Some(&denied), Some(&wkls)).is_err());
        drop(crate::tests::xml::deviations::take_unused_deviations(
            "CS-BC-M-14-20",
        ));
        Ok(())
    }
}
