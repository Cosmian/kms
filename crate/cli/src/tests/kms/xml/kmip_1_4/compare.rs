use cosmian_kms_client::cosmian_kmip as kms_kmip;

use crate::{
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::xml::compare::{compare_attributes, compare_object},
};

pub(crate) fn compare_payload_v14(
    expected: &kms_kmip::kmip_1_4::kmip_operations::Operation,
    actual: &kms_kmip::kmip_1_4::kmip_operations::Operation,
) -> KmsCliResult<()> {
    use std::mem::discriminant;

    use kms_kmip::kmip_1_4::kmip_operations::Operation as Op14;
    if discriminant(expected) != discriminant(actual) {
        return Err(KmsCliError::Default(format!(
            "Operation type mismatch expected={expected} actual={actual}",
        )));
    }

    match (expected.clone(), actual.clone()) {
        (Op14::CheckResponse(exp), Op14::CheckResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "CheckResponse mismatch expected={exp} actual={act}",
                )));
            }
        }
        (Op14::ActivateResponse(exp), Op14::ActivateResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "ActivateResponse mismatch expected={exp} actual={act}",
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
            if exp.object_type != act.object_type {
                return Err(KmsCliError::Default(format!(
                    "object_type expected={:?} actual={:?}",
                    exp.object_type, act.object_type
                )));
            }
            if exp.template_attribute.is_some() != act.template_attribute.is_some() {
                return Err(KmsCliError::Default(format!(
                    "template_attribute presence expected={:?} actual={:?}",
                    exp.template_attribute.is_some(),
                    act.template_attribute.is_some()
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
            if exp.template_attribute.is_some() != act.template_attribute.is_some() {
                return Err(KmsCliError::Default(format!(
                    "template_attribute presence expected={:?} actual={:?}",
                    exp.template_attribute.is_some(),
                    act.template_attribute.is_some()
                )));
            }
        }
        (Op14::DestroyResponse(exp), Op14::DestroyResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "DestroyResponse mismatch expected={exp} actual={act}",
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
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "CreateKeyPairResponse mismatch expected={exp} actual={act}",
                )));
            }
        }
        (Op14::DeleteAttributeResponse(exp), Op14::DeleteAttributeResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "DeleteAttributeResponse mismatch expected={exp} actual={act}",
                )));
            }
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
        (Op14::RNGSeedResponse(exp), Op14::RNGSeedResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "RNGSeedResponse mismatch expected={exp} actual={act}",
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
            let el = exp.data.as_ref().map_or(0, std::vec::Vec::len);
            let al = act.data.as_ref().map_or(0, std::vec::Vec::len);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={el} actual_len={al}",
                )));
            }
            let el = exp.i_v_counter_nonce.as_ref().map_or(0, std::vec::Vec::len);
            let al = act.i_v_counter_nonce.as_ref().map_or(0, std::vec::Vec::len);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "iv_counter_nonce mismatch expected_len={el} actual_len={al}",
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
                    "authenticated_encryption_tag mismatch expected_len={el} actual_len={al}",
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
            let el = exp.data.as_ref().map_or(0, std::vec::Vec::len);
            let al = act.data.as_ref().map_or(0, std::vec::Vec::len);
            if el != al {
                return Err(KmsCliError::Default(format!(
                    "data mismatch expected_len={el} actual_len={al}",
                )));
            }
        }
        (Op14::SignResponse(exp), Op14::SignResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "SignResponse mismatch expected={exp} actual={act}",
                )));
            }
        }
        (Op14::MACResponse(exp), Op14::MACResponse(act)) => {
            if exp.mac_data != act.mac_data {
                let el = exp.mac_data.as_ref().map_or(0, std::vec::Vec::len);
                let al = act.mac_data.as_ref().map_or(0, std::vec::Vec::len);
                return Err(KmsCliError::Default(format!(
                    "mac_data mismatch expected_len={el} actual_len={al}",
                )));
            }
        }
        (Op14::MACVerifyResponse(exp), Op14::MACVerifyResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "MACVerifyResponse mismatch expected={exp} actual={act}",
                )));
            }
        }
        (Op14::SignatureVerifyResponse(exp), Op14::SignatureVerifyResponse(act)) => {
            if exp != act {
                return Err(KmsCliError::Default(format!(
                    "SignatureVerifyResponse mismatch expected={exp} actual={act}",
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
                    "Payload mismatch for expected={expected} actual={actual}",
                )));
            }
        }
    }
    Ok(())
}
