use cosmian_kmip::kmip_2_1::{self};
use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_operations::Operation;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::xml::compare::{compare_attributes, compare_object},
};

pub(crate) fn compare_payload_v21(expected: &Operation, actual: &Operation) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}"
        )));
    }

    match (expected.clone(), actual.clone()) {
        (Operation::GetResponse(exp), Operation::GetResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                // Some servers set GetResponse.unique_identifier to the wrapping key's UID
                // when KeyWrappingData is present. Tolerate this specific divergence by
                // checking if the actual UID equals the EncryptionKeyInformation UID.
                use kmip_2_1::kmip_objects::Object as Obj;

                fn wrapping_encryption_uid(
                    obj: &kmip_2_1::kmip_objects::Object,
                ) -> Option<kmip_2_1::kmip_types::UniqueIdentifier> {
                    use Obj::{PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey};
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
                        "unique_identifier expected={exp_uid} actual={act_uid}",
                        exp_uid = exp.unique_identifier,
                        act_uid = act.unique_identifier
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
        (Operation::LocateResponse(exp), Operation::LocateResponse(act)) => {
            if exp.located_items != act.located_items {
                return Err(KmsCliError::Default(format!(
                    "located_items expected={:?} actual={:?}",
                    exp.located_items, act.located_items
                )));
            }
            if exp.unique_identifier != act.unique_identifier {
                match (
                    exp.unique_identifier.as_ref(),
                    act.unique_identifier.as_ref(),
                ) {
                    (Some(e), Some(a)) if e != a => {
                        let e_len = e.len();
                        let a_len = a.len();
                        return Err(KmsCliError::Default(format!(
                            "unique_identifier list mismatch expected_len={e_len} actual_len={a_len}"
                        )));
                    }
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
                        return Err(KmsCliError::Default(
                            "unique_identifier lists differ".to_string(),
                        ));
                    }
                    (None, Some(_)) => {
                        return Err(KmsCliError::Default(
                            "unique_identifier expected=None actual=Some".to_string(),
                        ));
                    }
                    (Some(_), None) => {
                        return Err(KmsCliError::Default(
                            "unique_identifier expected=Some actual=None".to_string(),
                        ));
                    }
                    (None, None) => {}
                }
            }
        }
        (Operation::RNGRetrieveResponse(exp), Operation::RNGRetrieveResponse(act)) => {
            if exp.data.len() != act.data.len() {
                let exp_len = exp.data.len();
                let act_len = act.data.len();
                return Err(KmsCliError::Default(format!(
                    "RNGRetrieveResponse data mismatch expected_len={exp_len} actual_len={act_len}"
                )));
            }
        }
        (Operation::EncryptResponse(exp), Operation::EncryptResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={exp_uid} actual={act_uid}",
                    exp_uid = exp.unique_identifier,
                    act_uid = act.unique_identifier
                )));
            }
            let el = exp.data.as_ref().map_or(0, std::vec::Vec::len);
            let al = act.data.as_ref().map_or(0, std::vec::Vec::len);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={el} actual_len={al}"
                )));
            }
            if exp.i_v_counter_nonce != act.i_v_counter_nonce {
                let el = exp.i_v_counter_nonce.as_ref().map_or(0, std::vec::Vec::len);
                let al = act.i_v_counter_nonce.as_ref().map_or(0, std::vec::Vec::len);
                return Err(KmsCliError::Default(format!(
                    "iv_counter_nonce mismatch expected_len={el} actual_len={al}"
                )));
            }
            let el = exp
                .authenticated_encryption_tag
                .as_ref()
                .map_or(0, std::vec::Vec::len);
            let al = act
                .authenticated_encryption_tag
                .as_ref()
                .map_or(0, std::vec::Vec::len);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "authenticated_encryption_tag mismatch expected_len={el} actual_len={al}"
                )));
            }
        }
        (Operation::DecryptResponse(exp), Operation::DecryptResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={exp_uid} actual={act_uid}",
                    exp_uid = exp.unique_identifier,
                    act_uid = act.unique_identifier
                )));
            }
            let el = exp.data.as_ref().map_or(0, |v| v.len());
            let al = act.data.as_ref().map_or(0, |v| v.len());
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={el} actual_len={al}"
                )));
            }
        }
        (Operation::GetAttributesResponse(exp), Operation::GetAttributesResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={exp_uid} actual={act_uid}",
                    exp_uid = exp.unique_identifier,
                    act_uid = act.unique_identifier
                )));
            }
            compare_attributes(&exp.attributes, &act.attributes)?;
        }
        (Operation::GetAttributeListResponse(exp), Operation::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={exp_uid} actual={act_uid}",
                    exp_uid = exp.unique_identifier,
                    act_uid = act.unique_identifier
                )));
            }
            // Cannot reliably compare attribute_references list as servers may return
            // different sets of attributes compared to SKFF - Symmetric Key Format and Features.
            // if exp.attribute_references != act.attribute_references {
            //     return Err(KmsCliError::Default(format!(
            //         "attribute_references mismatch expected={:?} actual={:?}",
            //         exp.attribute_references, act.attribute_references
            //     )));
            // }
        }
        (Operation::ModifyAttributeResponse(exp), Operation::ModifyAttributeResponse(act)) => {
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
        (Operation::PKCS11Response(exp), Operation::PKCS11Response(act)) => {
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
            // Tolerate differences in PKCS11OutputParameters. Implementations may return
            // different binary encodings for C_GetInfo depending on backend/provider.
            // Intentionally skip content and presence comparison for this field.
            if exp.correlation_value != act.correlation_value {
                let el = exp.correlation_value.as_ref().map_or(0, std::vec::Vec::len);
                let al = act.correlation_value.as_ref().map_or(0, std::vec::Vec::len);
                return Err(KmsCliError::Default(format!(
                    "CorrelationValue mismatch expected_len={el} actual_len={al}"
                )));
            }
        }
        (Operation::QueryResponse(_exp), Operation::QueryResponse(_act)) => {
            // TODO: implement Query server side: should implement missing KMIP operations
        }
        // Common MAC/signature verification variants
        (Operation::MACResponse(exp), Operation::MACResponse(act)) => {
            if exp.mac_data != act.mac_data {
                let el = exp.mac_data.as_ref().map_or(0, std::vec::Vec::len);
                let al = act.mac_data.as_ref().map_or(0, std::vec::Vec::len);
                return Err(KmsCliError::Default(format!(
                    "mac_data mismatch expected_len={el} actual_len={al}"
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
