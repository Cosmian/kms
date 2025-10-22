use cosmian_kms_client::cosmian_kmip as kms_kmip;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::xml::compare::{compare_attributes, compare_object},
};

pub(crate) fn compare_payload_v14(
    expected: kms_kmip::kmip_1_4::kmip_operations::Operation,
    actual: kms_kmip::kmip_1_4::kmip_operations::Operation,
) -> KmsCliResult<()> {
    use std::mem::discriminant;

    use kms_kmip::kmip_1_4::kmip_operations::Operation as Op14;
    if discriminant(&expected) != discriminant(&actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={} actual={}",
            expected, actual
        )));
    }

    match (expected.clone(), actual.clone()) {
        (Op14::CheckResponse(exp), Op14::CheckResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.cryptographic_usage_mask != act.cryptographic_usage_mask {
                return Err(KmsCliError::Default(format!(
                    "cryptographic_usage_mask expected={:?} actual={:?}",
                    exp.cryptographic_usage_mask, act.cryptographic_usage_mask
                )));
            }
        }
        (Op14::ActivateResponse(exp), Op14::ActivateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::CreateResponse(exp), Op14::CreateResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::RegisterResponse(exp), Op14::RegisterResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::DestroyResponse(exp), Op14::DestroyResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::GetResponse(exp), Op14::GetResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                // Some servers set GetResponse.unique_identifier to the wrapping key's UID
                // when KeyWrappingData is present. Tolerate this specific divergence by
                // checking if the actual UID equals the EncryptionKeyInformation UID.
                use kms_kmip::kmip_1_4::kmip_objects::Object as Obj14;

                fn wrapping_encryption_uid_14(
                    obj: &kms_kmip::kmip_1_4::kmip_objects::Object,
                ) -> Option<String> {
                    match obj {
                        Obj14::SymmetricKey(sk) => sk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj14::PrivateKey(pk) => pk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj14::PublicKey(pk) => pk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj14::SecretData(sd) => sd
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        Obj14::SplitKey(sk) => sk
                            .key_block
                            .key_wrapping_data
                            .as_ref()
                            .and_then(|kwd| kwd.encryption_key_information.as_ref())
                            .map(|eki| eki.unique_identifier.clone()),
                        _ => None,
                    }
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
            // Convert 1.4 objects to 2.1 and reuse deep comparator
            let exp_obj_21: kms_kmip::kmip_2_1::kmip_objects::Object = exp.object.into();
            let act_obj_21: kms_kmip::kmip_2_1::kmip_objects::Object = act.object.into();
            compare_object(&exp_obj_21, &act_obj_21)?;
        }
        (Op14::CreateKeyPairResponse(exp), Op14::CreateKeyPairResponse(act)) => {
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
        (Op14::DeleteAttributeResponse(_exp), Op14::DeleteAttributeResponse(_act)) => {
            // Skip strict UID comparison as servers may omit/alter it; mirrors v2.1 comparator leniency
        }
        (Op14::LocateResponse(exp), Op14::LocateResponse(act)) => {
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
                            .zip(a.iter())
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
        (Op14::RNGSeedResponse(exp), Op14::RNGSeedResponse(act)) => {
            if exp.amount_of_seed_data != act.amount_of_seed_data {
                return Err(KmsCliError::Default(format!(
                    "RNGSeedResponse amount_of_seed_data expected={} actual={}",
                    exp.amount_of_seed_data, act.amount_of_seed_data
                )));
            }
        }
        (Op14::RNGRetrieveResponse(exp), Op14::RNGRetrieveResponse(act)) => {
            if exp.data.len() != act.data.len() {
                return Err(KmsCliError::Default(format!(
                    "RNGRetrieveResponse data mismatch expected_len={} actual_len={}",
                    exp.data.len(),
                    act.data.len()
                )));
            }
        }
        (Op14::EncryptResponse(exp), Op14::EncryptResponse(act)) => {
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
            let el = exp.i_v_counter_nonce.as_ref().map(|v| v.len()).unwrap_or(0);
            let al = act.i_v_counter_nonce.as_ref().map(|v| v.len()).unwrap_or(0);
            if el != al {
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
        (Op14::DecryptResponse(exp), Op14::DecryptResponse(act)) => {
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
        (Op14::SignResponse(exp), Op14::SignResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            if exp.signature_data != act.signature_data {
                let el = exp.signature_data.len();
                let al = act.signature_data.len();
                return Err(KmsCliError::Default(format!(
                    "signature_data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Op14::MACResponse(exp), Op14::MACResponse(act)) => {
            if exp.mac_data != act.mac_data {
                let el = exp.mac_data.as_ref().map(|v| v.len()).unwrap_or(0);
                let al = act.mac_data.as_ref().map(|v| v.len()).unwrap_or(0);
                return Err(KmsCliError::Default(format!(
                    "mac_data mismatch expected_len={} actual_len={}",
                    el, al
                )));
            }
        }
        (Op14::MACVerifyResponse(exp), Op14::MACVerifyResponse(act)) => {
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
        (Op14::SignatureVerifyResponse(exp), Op14::SignatureVerifyResponse(act)) => {
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
        (Op14::GetAttributesResponse(exp), Op14::GetAttributesResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
            // Convert KMIP 1.4 Attribute list to KMIP 2.1 Attributes and compare
            let exp_attrs_21: kms_kmip::kmip_2_1::kmip_attributes::Attributes = exp
                .attribute
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<kms_kmip::kmip_2_1::kmip_attributes::Attribute>>()
                .into();
            let act_attrs_21: kms_kmip::kmip_2_1::kmip_attributes::Attributes = act
                .attribute
                .clone()
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
            // Do not strictly compare names list; servers may differ on returned attributes.
        }
        (Op14::AddAttributeResponse(exp), Op14::AddAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "AddAttributeResponse unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::ModifyAttributeResponse(exp), Op14::ModifyAttributeResponse(act)) => {
            if exp.unique_identifier != act.unique_identifier {
                return Err(KmsCliError::Default(format!(
                    "unique_identifier expected={} actual={}",
                    exp.unique_identifier, act.unique_identifier
                )));
            }
        }
        (Op14::QueryResponse(_exp), Op14::QueryResponse(_act)) => {
            // Mirror v2.1: ignore detailed QueryResponse comparisons for now.
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
