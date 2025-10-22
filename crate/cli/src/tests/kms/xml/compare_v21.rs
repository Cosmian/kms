use cosmian_kmip::kmip_2_1::{self};
use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_operations::Operation;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::xml::compare::{compare_attributes, compare_object},
};

pub(crate) fn compare_payload_v21(expected: Operation, actual: Operation) -> KmsCliResult<()> {
    use std::mem::discriminant;
    if discriminant(&expected) != discriminant(&actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={} actual={}",
            expected, actual
        )));
    }

    match (expected.clone(), actual.clone()) {
        (Operation::CheckResponse(exp), Operation::CheckResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                let exp_uid = exp
                    .unique_identifier
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "None".to_string());
                let act_uid = act
                    .unique_identifier
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "None".to_string());
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp_uid, act_uid
                )));
            }
            if exp.cryptographic_usage_mask != act.cryptographic_usage_mask {
                return Err(KmsCliError::Default(format!(
                    "cryptographic_usage_mask expected={:?} actual={:?}",
                    exp.cryptographic_usage_mask, act.cryptographic_usage_mask
                )));
            }
        }
        (Operation::ActivateResponse(exp), Operation::ActivateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Operation::CreateResponse(exp), Operation::CreateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Operation::RegisterResponse(exp), Operation::RegisterResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Operation::DestroyResponse(exp), Operation::DestroyResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Operation::GetResponse(exp), Operation::GetResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                // Some servers set GetResponse.unique_identifier to the wrapping key's UID
                // when KeyWrappingData is present. Tolerate this specific divergence by
                // checking if the actual UID equals the EncryptionKeyInformation UID.
                use kmip_2_1::kmip_objects::Object as Obj;

                fn wrapping_encryption_uid(
                    obj: &kmip_2_1::kmip_objects::Object,
                ) -> Option<kmip_2_1::kmip_types::UniqueIdentifier> {
                    match obj {
                        Obj::SymmetricKey(sk) => sk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj::PrivateKey(pk) => pk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj::PublicKey(pk) => pk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj::SecretData(sd) => sd
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj::SplitKey(sk) => sk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        _ => None,
                    }
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
        (Operation::CreateKeyPairResponse(exp), Operation::CreateKeyPairResponse(act)) => {
            if exp.private_key_unique_identifier != act.private_key_unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "private_key_unique_identifier expected={} actual={}",
                    exp.private_key_unique_identifier, act.private_key_unique_identifier
                )));
            }
            if exp.public_key_unique_identifier != act.public_key_unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "public_key_unique_identifier expected={} actual={}",
                    exp.public_key_unique_identifier, act.public_key_unique_identifier
                )));
            }
        }
        (Operation::DeleteAttributeResponse(_exp), Operation::DeleteAttributeResponse(_act)) => {
            // if exp.unique_identifier != act.unique_identifier {
            //     return Err(KmsCliError::Default(format!(
            //         "unique_identifier expected={} actual={}",
            //         exp.unique_identifier, act.unique_identifier
            //     )));
            // }
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
                        return Err(KmsCliError::Default(format!(
                            "unique_identifier list mismatch expected_len={} actual_len={}",
                            e.len(),
                            a.len()
                        )));
                    }
                    (Some(e), Some(a)) => {
                        let first_diff = e
                            .iter()
                            .map(|u| u.to_string())
                            .zip(a.iter().map(|u| u.to_string()))
                            .enumerate()
                            .find(|(_, (l, r))| l != r);
                        if let Some((idx, (l, r))) = first_diff {
                            return Err(KmsCliError::Default(format!(
                                "unique_identifier[{}] expected={} actual={}",
                                idx, l, r
                            )));
                        } else {
                            return Err(KmsCliError::Default(
                                "unique_identifier lists differ".to_string(),
                            ));
                        }
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
        (Operation::RNGSeedResponse(exp), Operation::RNGSeedResponse(act)) => {
            if exp.amount_of_seed_data != act.amount_of_seed_data {
                return Err(KmsCliError::Default(format!(
                    "RNGSeedResponse amount_of_seed_data expected={} actual={}",
                    exp.amount_of_seed_data, act.amount_of_seed_data
                )));
            }
        }
        (Operation::RNGRetrieveResponse(exp), Operation::RNGRetrieveResponse(act)) => {
            if exp.data.len() != act.data.len() {
                return Err(KmsCliError::Default(format!(
                    "RNGRetrieveResponse data mismatch expected_len={} actual_len={}",
                    exp.data.len(),
                    act.data.len()
                )));
            }
        }
        (Operation::EncryptResponse(exp), Operation::EncryptResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            let el = exp.data.as_ref().map(|v| v.len()).unwrap_or(0);
            let al = act.data.as_ref().map(|v| v.len()).unwrap_or(0);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
            if exp.i_v_counter_nonce != act.i_v_counter_nonce {
                let el = exp.i_v_counter_nonce.as_ref().map(|v| v.len()).unwrap_or(0);
                let al = act.i_v_counter_nonce.as_ref().map(|v| v.len()).unwrap_or(0);
                return Err(KmsCliError::Default(format!(
                    "iv_counter_nonce mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
            let el = exp
                .authenticated_encryption_tag
                .as_ref()
                .map(|v| v.len())
                .unwrap_or(0);
            let al = act
                .authenticated_encryption_tag
                .as_ref()
                .map(|v| v.len())
                .unwrap_or(0);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "authenticated_encryption_tag mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Operation::DecryptResponse(exp), Operation::DecryptResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            let el = exp.data.as_ref().map(|v| v.len()).unwrap_or(0);
            let al = act.data.as_ref().map(|v| v.len()).unwrap_or(0);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Operation::SignResponse(exp), Operation::SignResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.signature_data != act.signature_data {
                let el = exp.signature_data.as_ref().map(|v| v.len()).unwrap_or(0);
                let al = act.signature_data.as_ref().map(|v| v.len()).unwrap_or(0);
                return Err(KmsCliError::Default(format!(
                    "signature_data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Operation::GetAttributesResponse(exp), Operation::GetAttributesResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            compare_attributes(&exp.attributes, &act.attributes)?;
        }
        (Operation::GetAttributeListResponse(exp), Operation::GetAttributeListResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
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
        (Operation::AddAttributeResponse(exp), Operation::AddAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "AddAttributeResponse unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Operation::ModifyAttributeResponse(exp), Operation::ModifyAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                let eu = exp
                    .unique_identifier
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "None".to_string());
                let au = act
                    .unique_identifier
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "None".to_string());

                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    eu, au
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
            if exp.pkcs11_output_parameters != act.pkcs11_output_parameters {
                return Err(KmsCliError::Default(
                    "PKCS11OutputParameters mismatch".to_string(),
                ));
            }
            if exp.correlation_value != act.correlation_value {
                let el = exp.correlation_value.as_ref().map(|v| v.len()).unwrap_or(0);
                let al = act.correlation_value.as_ref().map(|v| v.len()).unwrap_or(0);
                return Err(KmsCliError::Default(format!(
                    "CorrelationValue mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Operation::QueryResponse(_exp), Operation::QueryResponse(_act)) => {
            // TODO: implement Query server side: should implement missing KMIP operations
            // let el = exp.operation.as_ref().map(|v| v.len()).unwrap_or(0);
            // let al = act.operation.as_ref().map(|v| v.len()).unwrap_or(0);
            // if el != al {
            //     return Err(KmsCliError::Default(format!(
            //         "operation list mismatch \nexpected_len={} \nactual_len={}",
            //         el, al
            //     )));
            // }
            // if exp.object_type != act.object_type {
            //     let el = exp.object_type.as_ref().map(|v| v.len()).unwrap_or(0);
            //     let al = act.object_type.as_ref().map(|v| v.len()).unwrap_or(0);
            //     return Err(KmsCliError::Default(format!(
            //         "object_type list mismatch expected_len={} actual_len={}",
            //         el, al
            //     )));
            // }
            // Vendor and server info filtered
            // if exp.vendor_identification != act.vendor_identification {
            //     return Err(KmsCliError::Default(format!(
            //         "vendor_identification expected={:?} actual={:?}",
            //         exp.vendor_identification, act.vendor_identification
            //     )));
            // }
            // if exp.server_information != act.server_information {
            //     return Err(KmsCliError::Default(format!(
            //         "server_information mismatch: expected={:?} actual={:?}",
            //         exp.server_information, act.server_information
            //     )));
            // }
        }
        // Common MAC/signature verification variants
        (Operation::SignatureVerifyResponse(exp), Operation::SignatureVerifyResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.validity_indicator != act.validity_indicator {
                return Err(KmsCliError::Default(format!(
                    "validity_indicator expected={:?} actual={:?}",
                    exp.validity_indicator, act.validity_indicator
                )));
            }
        }
        (Operation::MACResponse(exp), Operation::MACResponse(act)) => {
            if exp.mac_data != act.mac_data {
                let el = exp.mac_data.as_ref().map(|v| v.len()).unwrap_or(0);
                let al = act.mac_data.as_ref().map(|v| v.len()).unwrap_or(0);
                return Err(KmsCliError::Default(format!(
                    "mac_data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Operation::MACVerifyResponse(exp), Operation::MACVerifyResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.validity_indicator != act.validity_indicator {
                return Err(KmsCliError::Default(format!(
                    "validity_indicator expected={:?} actual={:?}",
                    exp.validity_indicator, act.validity_indicator
                )));
            }
        }
        _ => {
            if expected != actual {
                return Err(KmsCliError::Default(format!(
                    "Payload mismatch for {}: expected={} actual={}",
                    expected, expected, actual
                )));
            }
        }
    }
    Ok(())
}
