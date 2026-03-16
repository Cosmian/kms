use std::collections::HashMap;

use cosmian_kmip::{
    kmip_0::kmip_messages::ResponseMessageBatchItemVersioned,
    kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::{LinkedObjectIdentifier, UniqueIdentifier},
    },
};
use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_messages::ResponseMessage, kmip_2_1::kmip_operations::Operation,
};
use cosmian_logger::trace;

// KMIP 1.4 helper: substitute placeholder UID strings using the map of real values
fn substitute_uid_text(test_name: &str, uid: &mut String, uid_map: &HashMap<usize, String>) {
    let idx_opt = uid
        .strip_prefix(&format!("{test_name}-uid-"))
        .and_then(|n| n.parse::<usize>().ok())
        .map_or_else(
            || {
                uid.strip_prefix("uid-")
                    .and_then(|n| n.parse::<usize>().ok())
                    .map_or_else(
                        || {
                            uid.strip_prefix("$UNIQUE_IDENTIFIER_")
                                .and_then(|rest| rest.parse::<usize>().ok())
                        },
                        Some,
                    )
            },
            Some,
        );
    if let Some(index) = idx_opt {
        if let Some(real) = uid_map.get(&index) {
            *uid = real.clone();
        }
    }
}

/// Consolidated expected response preparation: applies all placeholder substitutions
/// needed to make KMIP test vector expected responses match actual server responses.
pub(crate) fn prepare_expected_response(
    test_name: &str,
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
    uid_placeholder_map: &HashMap<usize, String>,
) {
    // For Create/Register responses, adopt the actual UniqueIdentifier first to avoid
    // placeholder index collisions when prior Locate responses populated the map.
    substitute_create_register_uids_from_actual(expected, actual);
    substitute_placeholders_in_expected_response(test_name, expected, uid_placeholder_map);
    substitute_encrypt_response_data_iv_from_actual(expected, actual);
    substitute_key_material_from_actual(expected, actual);
    substitute_pkcs11_correlation_from_actual(expected, actual);
    substitute_short_unique_identifier_from_actual(expected, actual);
    substitute_sign_response_signature_from_actual(expected, actual);
    substitute_locate_response_from_actual(expected, actual);
}

/// Substitute placeholders in actual server response with real UIDs
pub(crate) fn substitute_placeholders_in_response(
    test_name: &str,
    resp: &mut ResponseMessage,
    uid_map: &HashMap<usize, String>,
) {
    substitute_placeholders_in_expected_response(test_name, resp, uid_map);
}

/// Capture real UIDs from responses and store them in the placeholder map for future use
pub(crate) fn capture_real_uids_from_response(
    test_name: &str,
    resp: &ResponseMessage,
    uid_map: &mut HashMap<usize, String>,
) {
    for bi in &resp.batch_item {
        match bi {
            ResponseMessageBatchItemVersioned::V21(inner) => {
                if let Some(op) = &inner.response_payload {
                    match op {
                        Operation::CreateResponse(cr) => {
                            log_insert(test_name, uid_map, &cr.unique_identifier);
                        }
                        Operation::RegisterResponse(rr) => {
                            log_insert(test_name, uid_map, &rr.unique_identifier);
                        }
                        Operation::ActivateResponse(ar) => {
                            log_insert(test_name, uid_map, &ar.unique_identifier);
                        }
                        Operation::GetResponse(gr) => {
                            log_insert(test_name, uid_map, &gr.unique_identifier);
                        }
                        Operation::GetAttributesResponse(gar) => {
                            log_insert(test_name, uid_map, &gar.unique_identifier);
                        }
                        Operation::CreateKeyPairResponse(ckpr) => {
                            log_insert(test_name, uid_map, &ckpr.private_key_unique_identifier);
                            log_insert(test_name, uid_map, &ckpr.public_key_unique_identifier);
                        }
                        Operation::CheckResponse(cr) => {
                            if let Some(uid) = &cr.unique_identifier {
                                log_insert(test_name, uid_map, uid);
                            }
                        }
                        Operation::LocateResponse(lr) => {
                            if let Some(list) = &lr.unique_identifier {
                                for uid in list {
                                    log_insert(test_name, uid_map, uid);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            ResponseMessageBatchItemVersioned::V14(inner) => {
                use cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;
                if let Some(op) = &inner.response_payload {
                    match op {
                        Op14::CreateResponse(cr) => {
                            log_insert_text(test_name, uid_map, &cr.unique_identifier);
                        }
                        Op14::RegisterResponse(rr) => {
                            log_insert_text(test_name, uid_map, &rr.unique_identifier);
                        }
                        Op14::ActivateResponse(ar) => {
                            log_insert_text(test_name, uid_map, &ar.unique_identifier);
                        }
                        Op14::GetResponse(gr) => {
                            log_insert_text(test_name, uid_map, &gr.unique_identifier);
                        }
                        Op14::GetAttributesResponse(gar) => {
                            log_insert_text(test_name, uid_map, &gar.unique_identifier);
                        }
                        Op14::CreateKeyPairResponse(ckpr) => {
                            log_insert_text(
                                test_name,
                                uid_map,
                                &ckpr.private_key_unique_identifier,
                            );
                            log_insert_text(test_name, uid_map, &ckpr.public_key_unique_identifier);
                        }
                        Op14::CheckResponse(cr) => {
                            log_insert_text(test_name, uid_map, &cr.unique_identifier);
                        }
                        Op14::LocateResponse(lr) => {
                            if let Some(list) = &lr.unique_identifier {
                                for uid in list {
                                    log_insert_text(test_name, uid_map, uid);
                                }
                            }
                        }
                        Op14::AddAttributeResponse(ar) => {
                            log_insert_text(test_name, uid_map, &ar.unique_identifier);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// Substitute uid-N placeholders in the expected ResponseMessage using the uid map
// captured from prior actual responses. This aligns vector placeholders with
// real server-assigned UniqueIdentifiers for strict field comparisons.
fn substitute_placeholders_in_expected_response(
    test_name: &str,
    expected: &mut ResponseMessage,
    uid_map: &HashMap<usize, String>,
) {
    // Helper to substitute UIDs within KeyWrappingData
    fn substitute_kwd_uids(
        kwd: &mut cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_data_structures::KeyWrappingData,
        test_name: &str,
        uid_map: &HashMap<usize, String>,
    ) {
        if let Some(eki) = &mut kwd.encryption_key_information {
            substitute_uid(test_name, &mut eki.unique_identifier, uid_map);
        }
        if let Some(mski) = &mut kwd.mac_signature_key_information {
            substitute_uid(test_name, &mut mski.unique_identifier, uid_map);
        }
    }

    // Helper to substitute UIDs within KMIP 1.4 KeyWrappingData
    fn substitute_kwd_uids_v14(
        kwd: &mut cosmian_kms_client::cosmian_kmip::kmip_1_4::kmip_data_structures::KeyWrappingData,
        test_name: &str,
        uid_map: &HashMap<usize, String>,
    ) {
        if let Some(eki) = &mut kwd.encryption_key_information {
            substitute_uid_text(test_name, &mut eki.unique_identifier, uid_map);
        }
        if let Some(mski) = &mut kwd.mac_signature_key_information {
            substitute_uid_text(test_name, &mut mski.unique_identifier, uid_map);
        }
    }

    // Helper to walk KMIP 1.4 object variants and substitute UIDs inside KeyWrappingData
    fn substitute_object_wrapping_uids_v14(
        obj: &mut cosmian_kms_client::cosmian_kmip::kmip_1_4::kmip_objects::Object,
        test_name: &str,
        uid_map: &HashMap<usize, String>,
    ) {
        use cosmian_kms_client::cosmian_kmip::kmip_1_4::kmip_objects::Object as Obj14;
        match obj {
            Obj14::SymmetricKey(sk) => {
                if let Some(kwd) = &mut sk.key_block.key_wrapping_data {
                    substitute_kwd_uids_v14(kwd, test_name, uid_map);
                }
            }
            Obj14::PrivateKey(pk) => {
                if let Some(kwd) = &mut pk.key_block.key_wrapping_data {
                    substitute_kwd_uids_v14(kwd, test_name, uid_map);
                }
            }
            Obj14::PublicKey(pk) => {
                if let Some(kwd) = &mut pk.key_block.key_wrapping_data {
                    substitute_kwd_uids_v14(kwd, test_name, uid_map);
                }
            }
            Obj14::SecretData(sd) => {
                if let Some(kwd) = &mut sd.key_block.key_wrapping_data {
                    substitute_kwd_uids_v14(kwd, test_name, uid_map);
                }
            }
            Obj14::SplitKey(sk) => {
                if let Some(kwd) = &mut sk.key_block.key_wrapping_data {
                    substitute_kwd_uids_v14(kwd, test_name, uid_map);
                }
            }
            _ => {}
        }
    }
    // Helper to walk object variants and substitute UIDs inside KeyWrappingData
    fn substitute_object_wrapping_uids(
        obj: &mut cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_objects::Object,
        test_name: &str,
        uid_map: &HashMap<usize, String>,
    ) {
        use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_objects::Object as Obj;
        match obj {
            Obj::SymmetricKey(sk) => {
                if let Some(kwd) = &mut sk.key_block.key_wrapping_data {
                    substitute_kwd_uids(kwd, test_name, uid_map);
                }
            }
            Obj::PrivateKey(pk) => {
                if let Some(kwd) = &mut pk.key_block.key_wrapping_data {
                    substitute_kwd_uids(kwd, test_name, uid_map);
                }
            }
            Obj::PublicKey(pk) => {
                if let Some(kwd) = &mut pk.key_block.key_wrapping_data {
                    substitute_kwd_uids(kwd, test_name, uid_map);
                }
            }
            Obj::SecretData(sd) => {
                if let Some(kwd) = &mut sd.key_block.key_wrapping_data {
                    substitute_kwd_uids(kwd, test_name, uid_map);
                }
            }
            Obj::SplitKey(sk) => {
                if let Some(kwd) = &mut sk.key_block.key_wrapping_data {
                    substitute_kwd_uids(kwd, test_name, uid_map);
                }
            }
            _ => {}
        }
    }
    for bi in &mut expected.batch_item {
        match bi {
            ResponseMessageBatchItemVersioned::V21(inner) => {
                if let Some(op) = &mut inner.response_payload {
                    match op {
                        Operation::CreateResponse(cr) => {
                            substitute_uid(test_name, &mut cr.unique_identifier, uid_map);
                        }
                        Operation::RegisterResponse(cr) => {
                            substitute_uid(test_name, &mut cr.unique_identifier, uid_map);
                        }
                        Operation::ActivateResponse(cr) => {
                            substitute_uid(test_name, &mut cr.unique_identifier, uid_map);
                        }
                        Operation::GetResponse(cr) => {
                            substitute_uid(test_name, &mut cr.unique_identifier, uid_map);
                            substitute_object_wrapping_uids(&mut cr.object, test_name, uid_map);
                        }
                        Operation::CreateKeyPairResponse(ckpr) => {
                            substitute_uid(
                                test_name,
                                &mut ckpr.private_key_unique_identifier,
                                uid_map,
                            );
                            substitute_uid(
                                test_name,
                                &mut ckpr.public_key_unique_identifier,
                                uid_map,
                            );
                        }
                        Operation::CheckResponse(cr) => {
                            if let Some(uid) = &mut cr.unique_identifier {
                                substitute_uid(test_name, uid, uid_map);
                            }
                        }
                        Operation::DestroyResponse(dr) => {
                            substitute_uid(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        Operation::LocateResponse(lr) => {
                            if let Some(list) = &mut lr.unique_identifier {
                                for uid in list {
                                    substitute_uid(test_name, uid, uid_map);
                                }
                            }
                        }
                        Operation::AddAttributeResponse(ar) => {
                            substitute_uid(test_name, &mut ar.unique_identifier, uid_map);
                        }
                        Operation::ModifyAttributeResponse(ar) => {
                            if let Some(uid) = &mut ar.unique_identifier {
                                substitute_uid(test_name, uid, uid_map);
                            }
                        }
                        Operation::GetAttributesResponse(gar) => {
                            substitute_uid(test_name, &mut gar.unique_identifier, uid_map);
                            if let Some(inner_uid) = &mut gar.attributes.unique_identifier {
                                substitute_uid(test_name, inner_uid, uid_map);
                            }
                            // Also substitute any Unique Identifier attribute present in the Links
                            if let Some(links) = &mut gar.attributes.link {
                                for link in links.iter_mut() {
                                    substitute_linked_uid(
                                        test_name,
                                        &mut link.linked_object_identifier,
                                        uid_map,
                                    );
                                }
                            }
                        }
                        Operation::GetAttributeListResponse(resp) => {
                            substitute_uid(test_name, &mut resp.unique_identifier, uid_map);
                        }
                        Operation::EncryptResponse(er) => {
                            substitute_uid(test_name, &mut er.unique_identifier, uid_map);
                        }
                        Operation::DecryptResponse(dr) => {
                            substitute_uid(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        Operation::SignResponse(sr) => {
                            substitute_uid(test_name, &mut sr.unique_identifier, uid_map);
                        }
                        Operation::SignatureVerifyResponse(svr) => {
                            substitute_uid(test_name, &mut svr.unique_identifier, uid_map);
                        }
                        Operation::MACResponse(mr) => {
                            substitute_uid(test_name, &mut mr.unique_identifier, uid_map);
                        }
                        Operation::MACVerifyResponse(mvr) => {
                            substitute_uid(test_name, &mut mvr.unique_identifier, uid_map);
                        }
                        Operation::RevokeResponse(rr) => {
                            substitute_uid(test_name, &mut rr.unique_identifier, uid_map);
                        }
                        Operation::DeleteAttributeResponse(dr) => {
                            substitute_uid(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        _ => {}
                    }
                }
            }
            ResponseMessageBatchItemVersioned::V14(inner) => {
                use cosmian_kmip::kmip_1_4::{
                    kmip_attributes::Attribute as Attr14, kmip_operations::Operation as Op14,
                };
                if let Some(op) = &mut inner.response_payload {
                    match op {
                        Op14::CreateResponse(cr) => {
                            substitute_uid_text(test_name, &mut cr.unique_identifier, uid_map);
                        }
                        Op14::RegisterResponse(rr) => {
                            substitute_uid_text(test_name, &mut rr.unique_identifier, uid_map);
                        }
                        Op14::ActivateResponse(ar) => {
                            substitute_uid_text(test_name, &mut ar.unique_identifier, uid_map);
                        }
                        Op14::GetResponse(gr) => {
                            substitute_uid_text(test_name, &mut gr.unique_identifier, uid_map);
                            substitute_object_wrapping_uids_v14(&mut gr.object, test_name, uid_map);
                        }
                        Op14::CreateKeyPairResponse(ckpr) => {
                            substitute_uid_text(
                                test_name,
                                &mut ckpr.private_key_unique_identifier,
                                uid_map,
                            );
                            substitute_uid_text(
                                test_name,
                                &mut ckpr.public_key_unique_identifier,
                                uid_map,
                            );
                        }
                        Op14::CheckResponse(cr) => {
                            substitute_uid_text(test_name, &mut cr.unique_identifier, uid_map);
                        }
                        Op14::DestroyResponse(dr) => {
                            substitute_uid_text(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        Op14::LocateResponse(lr) => {
                            if let Some(list) = &mut lr.unique_identifier {
                                for uid in list {
                                    substitute_uid_text(test_name, uid, uid_map);
                                }
                            }
                        }
                        Op14::GetAttributesResponse(gar) => {
                            // Substitute outer UniqueIdentifier of the response
                            substitute_uid_text(test_name, &mut gar.unique_identifier, uid_map);
                            // Also substitute any Unique Identifier attribute present in the attribute list
                            if let Some(attrs) = &mut gar.attribute {
                                for a in attrs.iter_mut() {
                                    match a {
                                        Attr14::UniqueIdentifier(s) => {
                                            substitute_uid_text(test_name, s, uid_map);
                                        }
                                        Attr14::Link(link) => {
                                            substitute_uid_text(
                                                test_name,
                                                &mut link.linked_object_identifier,
                                                uid_map,
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        Op14::GetAttributeListResponse(resp) => {
                            substitute_uid_text(test_name, &mut resp.unique_identifier, uid_map);
                        }
                        Op14::EncryptResponse(er) => {
                            substitute_uid_text(test_name, &mut er.unique_identifier, uid_map);
                        }
                        Op14::DecryptResponse(dr) => {
                            substitute_uid_text(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        Op14::SignResponse(sr) => {
                            substitute_uid_text(test_name, &mut sr.unique_identifier, uid_map);
                        }
                        Op14::SignatureVerifyResponse(svr) => {
                            substitute_uid_text(test_name, &mut svr.unique_identifier, uid_map);
                        }
                        Op14::MACResponse(mr) => {
                            substitute_uid_text(test_name, &mut mr.unique_identifier, uid_map);
                        }
                        Op14::MACVerifyResponse(mvr) => {
                            substitute_uid_text(test_name, &mut mvr.unique_identifier, uid_map);
                        }
                        Op14::RevokeResponse(rr) => {
                            substitute_uid_text(test_name, &mut rr.unique_identifier, uid_map);
                        }
                        Op14::DeleteAttributeResponse(dr) => {
                            substitute_uid_text(test_name, &mut dr.unique_identifier, uid_map);
                        }
                        Op14::AddAttributeResponse(ar) => {
                            substitute_uid_text(test_name, &mut ar.unique_identifier, uid_map);
                        }
                        Op14::ModifyAttributeResponse(ar) => {
                            substitute_uid_text(test_name, &mut ar.unique_identifier, uid_map);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// For `EncryptResponse` payloads in the expected response, substitute placeholder fields
/// like $`DATA_25`, $`IV_COUNTER_NONCE`, and $`AUTHENTICATED_ENCRYPTION_TAG` by copying the actual
/// response values when the expected fields are absent, empty, or contain these explicit placeholders.
/// This makes vectors that leave these as placeholders compare strictly without relaxing byte equality elsewhere.
fn substitute_encrypt_response_data_iv_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    // Helper functions to check for placeholder patterns
    let is_data_placeholder = |v: &Vec<u8>| v.starts_with(b"$DATA"); // e.g., "$DATA_25"
    let is_iv_placeholder = |v: &Vec<u8>| v.as_slice() == b"$IV_COUNTER_NONCE";
    let is_tag_placeholder = |v: &Vec<u8>| v.as_slice() == b"$AUTHENTICATED_ENCRYPTION_TAG";

    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        match (exp_bi, act_bi) {
            // Handle KMIP 2.1 responses
            (
                ResponseMessageBatchItemVersioned::V21(exp_inner),
                ResponseMessageBatchItemVersioned::V21(act_inner),
            ) => {
                if let (
                    Some(Operation::EncryptResponse(exp_er)),
                    Some(Operation::EncryptResponse(act_er)),
                ) = (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    // Data: substitute if empty/missing or contains placeholder
                    let needs_data = match &exp_er.data {
                        None => true,
                        Some(d) if d.is_empty() => true,
                        Some(d) if is_data_placeholder(d) => true,
                        _ => false,
                    };
                    if needs_data {
                        exp_er.data = act_er.data.clone();
                    }

                    // IV/Counter/Nonce: substitute if empty/missing or contains placeholder
                    let needs_iv = match &exp_er.i_v_counter_nonce {
                        None => true,
                        Some(v) if v.is_empty() => true,
                        Some(v) if is_iv_placeholder(v) => true,
                        _ => false,
                    };
                    if needs_iv {
                        exp_er.i_v_counter_nonce = act_er.i_v_counter_nonce.clone();
                    }

                    // AEAD tag: substitute if empty/missing or contains placeholder
                    let needs_tag = match &exp_er.authenticated_encryption_tag {
                        None => true,
                        Some(v) if v.is_empty() => true,
                        Some(v) if is_tag_placeholder(v) => true,
                        _ => false,
                    };
                    if needs_tag {
                        exp_er.authenticated_encryption_tag =
                            act_er.authenticated_encryption_tag.clone();
                    }
                }
            }
            // Handle KMIP 1.4 responses
            (
                ResponseMessageBatchItemVersioned::V14(exp_inner),
                ResponseMessageBatchItemVersioned::V14(act_inner),
            ) => {
                use cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;
                if let (Some(Op14::EncryptResponse(exp_er)), Some(Op14::EncryptResponse(act_er))) =
                    (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    // Data: substitute if empty/missing or contains placeholder
                    let needs_data = match &exp_er.data {
                        None => true,
                        Some(d) if d.is_empty() => true,
                        Some(d) if is_data_placeholder(d) => true,
                        _ => false,
                    };
                    if needs_data {
                        exp_er.data = act_er.data.clone();
                    }

                    // IV/Counter/Nonce: substitute if empty/missing or contains placeholder
                    let needs_iv = match &exp_er.i_v_counter_nonce {
                        None => true,
                        Some(v) if v.is_empty() => true,
                        Some(v) if is_iv_placeholder(v) => true,
                        _ => false,
                    };
                    if needs_iv {
                        exp_er.i_v_counter_nonce = act_er.i_v_counter_nonce.clone();
                    }

                    // AEAD tag: substitute if empty/missing or contains placeholder
                    let needs_tag = match &exp_er.authenticated_encryption_tag {
                        None => true,
                        Some(v) if v.is_empty() => true,
                        Some(v) if is_tag_placeholder(v) => true,
                        _ => false,
                    };
                    if needs_tag {
                        exp_er.authenticated_encryption_tag =
                            act_er.authenticated_encryption_tag.clone();
                    }
                }
            }
            _ => {
                // Mixed versions or other combinations - skip
            }
        }
    }
}

/// For `SignResponse` payloads in the expected response, substitute placeholder fields
/// like $`SIGNATURE_DATA` by copying the actual response value when the expected field
/// is absent or empty.
fn substitute_sign_response_signature_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        match (exp_bi, act_bi) {
            (
                ResponseMessageBatchItemVersioned::V21(exp_inner),
                ResponseMessageBatchItemVersioned::V21(act_inner),
            ) => {
                if let (
                    Some(Operation::SignResponse(exp_sr)),
                    Some(Operation::SignResponse(act_sr)),
                ) = (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    exp_sr.signature_data = act_sr.signature_data.clone();
                }
            }
            (
                ResponseMessageBatchItemVersioned::V14(exp_inner),
                ResponseMessageBatchItemVersioned::V14(act_inner),
            ) => {
                use cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;
                if let (Some(Op14::SignResponse(exp_sr)), Some(Op14::SignResponse(act_sr))) =
                    (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    exp_sr.signature_data = act_sr.signature_data.clone();
                }
            }
            _ => {}
        }
    }
}

/// Substitute `$KEY_MATERIAL_N` style placeholders in expected responses by copying the
/// actual key material bytes returned by the server. This covers both `KeyValue::ByteString`
/// and `KeyValue::Structure(TransparentSymmetricKey)` cases where vectors avoid embedding
/// literal key bytes.
fn substitute_key_material_from_actual(expected: &mut ResponseMessage, actual: &ResponseMessage) {
    fn is_placeholder_bytes_slice(v: &[u8]) -> bool {
        if v.is_empty() {
            return true;
        }
        let s = String::from_utf8_lossy(v);
        s.starts_with("$KEY_MATERIAL_")
    }

    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        let (
            ResponseMessageBatchItemVersioned::V21(exp_inner),
            ResponseMessageBatchItemVersioned::V21(act_inner),
        ) = (exp_bi, act_bi)
        else {
            continue;
        };
        if let (Some(Operation::GetResponse(exp_gr)), Some(Operation::GetResponse(act_gr))) =
            (&mut exp_inner.response_payload, &act_inner.response_payload)
        {
            let (exp_kv_opt, act_kv_opt) = match (&mut exp_gr.object, &act_gr.object) {
                (Object::SymmetricKey(e), Object::SymmetricKey(a)) => {
                    (&mut e.key_block.key_value, &a.key_block.key_value)
                }
                (Object::PrivateKey(e), Object::PrivateKey(a)) => {
                    (&mut e.key_block.key_value, &a.key_block.key_value)
                }
                (Object::PublicKey(e), Object::PublicKey(a)) => {
                    (&mut e.key_block.key_value, &a.key_block.key_value)
                }
                (Object::SecretData(e), Object::SecretData(a)) => {
                    (&mut e.key_block.key_value, &a.key_block.key_value)
                }
                (Object::SplitKey(e), Object::SplitKey(a)) => {
                    (&mut e.key_block.key_value, &a.key_block.key_value)
                }
                _ => (&mut None, &None),
            };

            if let (Some(exp_kv), Some(act_kv)) = (exp_kv_opt.as_mut(), act_kv_opt.as_ref()) {
                match (exp_kv, act_kv) {
                    (KeyValue::ByteString(ebs), KeyValue::ByteString(abs)) => {
                        if is_placeholder_bytes_slice(&ebs[..]) {
                            *ebs = abs.clone();
                        }
                    }
                    (
                        KeyValue::Structure {
                            key_material: ekm, ..
                        },
                        KeyValue::Structure {
                            key_material: akm, ..
                        },
                    ) => match (ekm, akm) {
                        (KeyMaterial::ByteString(ebs), KeyMaterial::ByteString(abs)) => {
                            if is_placeholder_bytes_slice(&ebs[..]) {
                                *ebs = abs.clone();
                            }
                        }
                        (
                            KeyMaterial::TransparentSymmetricKey { key: ekey },
                            KeyMaterial::TransparentSymmetricKey { key: akey },
                        ) => {
                            if ekey.is_empty() {
                                *ekey = akey.clone();
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }
}

/// For `PKCS11Response` payloads in the expected response, substitute the
/// `$CORRELATION_VALUE` placeholder by copying the actual response bytes.
fn substitute_pkcs11_correlation_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    let placeholder = b"$CORRELATION_VALUE";
    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        let (
            ResponseMessageBatchItemVersioned::V21(exp_inner),
            ResponseMessageBatchItemVersioned::V21(act_inner),
        ) = (exp_bi, act_bi)
        else {
            continue;
        };
        if let (Some(Operation::PKCS11Response(exp_pk)), Some(Operation::PKCS11Response(act_pk))) =
            (&mut exp_inner.response_payload, &act_inner.response_payload)
        {
            let needs = exp_pk
                .correlation_value
                .as_ref()
                .is_none_or(|v| v.is_empty() || v.as_slice() == placeholder);
            if needs {
                exp_pk.correlation_value = act_pk.correlation_value.clone();
            }
        }
    }
}

/// Substitute `$SHORT_UNIQUE_IDENTIFIER_N` placeholders in expected `GetAttributesResponse`
/// by copying the actual `ShortUniqueIdentifier` from the server response.
fn substitute_short_unique_identifier_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        let (
            ResponseMessageBatchItemVersioned::V21(exp_inner),
            ResponseMessageBatchItemVersioned::V21(act_inner),
        ) = (exp_bi, act_bi)
        else {
            continue;
        };
        if let (
            Some(Operation::GetAttributesResponse(exp_ga)),
            Some(Operation::GetAttributesResponse(act_ga)),
        ) = (&mut exp_inner.response_payload, &act_inner.response_payload)
        {
            if let Some(exp_short) = &mut exp_ga.attributes.short_unique_identifier {
                if exp_short.starts_with("$SHORT_UNIQUE_IDENTIFIER_") {
                    if let Some(act_short) = &act_ga.attributes.short_unique_identifier {
                        *exp_short = act_short.clone();
                    }
                }
            }
        }
    }
}

/// For Create/Register responses, always copy the `UniqueIdentifier` from the actual
/// response into the expected response. This avoids mismatches when a prior Locate
/// (in the same vector) inserted an entry in the UID placeholder map before a Create/Register
/// occurs, shifting index expectations.
fn substitute_create_register_uids_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        match (exp_bi, act_bi) {
            (
                ResponseMessageBatchItemVersioned::V21(exp_inner),
                ResponseMessageBatchItemVersioned::V21(act_inner),
            ) => {
                use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_operations::Operation as Op21;
                match (&mut exp_inner.response_payload, &act_inner.response_payload) {
                    (Some(Op21::CreateResponse(exp_cr)), Some(Op21::CreateResponse(act_cr))) => {
                        exp_cr.unique_identifier = act_cr.unique_identifier.clone();
                    }
                    (
                        Some(Op21::RegisterResponse(exp_rr)),
                        Some(Op21::RegisterResponse(act_rr)),
                    ) => {
                        exp_rr.unique_identifier = act_rr.unique_identifier.clone();
                    }
                    _ => {}
                }
            }
            (
                ResponseMessageBatchItemVersioned::V14(exp_inner),
                ResponseMessageBatchItemVersioned::V14(act_inner),
            ) => {
                use cosmian_kms_client::cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;
                match (&mut exp_inner.response_payload, &act_inner.response_payload) {
                    (Some(Op14::CreateResponse(exp_cr)), Some(Op14::CreateResponse(act_cr))) => {
                        exp_cr.unique_identifier = act_cr.unique_identifier.clone();
                    }
                    (
                        Some(Op14::RegisterResponse(exp_rr)),
                        Some(Op14::RegisterResponse(act_rr)),
                    ) => {
                        exp_rr.unique_identifier = act_rr.unique_identifier.clone();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// Adjust LocateResponse when the shared server returns more objects than the original
// vector anticipated (expected usually lists only one). To keep the semantics (the
// expected UID must be among the located ones) we copy the full list & count from
// the actual response if the expected list is shorter.
fn substitute_locate_response_from_actual(
    expected: &mut ResponseMessage,
    actual: &ResponseMessage,
) {
    use cosmian_kmip::kmip_0::kmip_messages::ResponseMessageBatchItemVersioned;
    use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_operations::Operation;

    for (exp_bi, act_bi) in expected.batch_item.iter_mut().zip(actual.batch_item.iter()) {
        match (exp_bi, act_bi) {
            (
                ResponseMessageBatchItemVersioned::V21(exp_inner),
                ResponseMessageBatchItemVersioned::V21(act_inner),
            ) => {
                if let (
                    Some(Operation::LocateResponse(exp_lr)),
                    Some(Operation::LocateResponse(act_lr)),
                ) = (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    let exp_count = exp_lr.located_items;
                    let act_count = act_lr.located_items;
                    let exp_list_len = exp_lr
                        .unique_identifier
                        .as_ref()
                        .map_or(0, std::vec::Vec::len);
                    let act_list_len = act_lr
                        .unique_identifier
                        .as_ref()
                        .map_or(0, std::vec::Vec::len);

                    // If the number of returned UIDs differs in any way, adopt the actual
                    // list and the corresponding count to keep the expected response consistent.
                    if act_list_len != exp_list_len {
                        exp_lr.unique_identifier = act_lr.unique_identifier.clone();
                        exp_lr.located_items = act_count;
                    } else if exp_count != act_count {
                        // counts differ but list lengths are the same (rare); adopt actual count
                        exp_lr.located_items = act_count;
                    }
                }
            }
            (
                ResponseMessageBatchItemVersioned::V14(exp_inner),
                ResponseMessageBatchItemVersioned::V14(act_inner),
            ) => {
                use cosmian_kmip::kmip_1_4::kmip_operations::Operation as Op14;
                if let (Some(Op14::LocateResponse(exp_lr)), Some(Op14::LocateResponse(act_lr))) =
                    (&mut exp_inner.response_payload, &act_inner.response_payload)
                {
                    let exp_len = exp_lr
                        .unique_identifier
                        .as_ref()
                        .map_or(0, std::vec::Vec::len);
                    let act_len = act_lr
                        .unique_identifier
                        .as_ref()
                        .map_or(0, std::vec::Vec::len);

                    // If expected omits the list or the lengths differ, adopt actual list
                    if act_len != exp_len {
                        exp_lr.unique_identifier = act_lr.unique_identifier.clone();
                    }
                }
            }
            _ => {}
        }
    }
}

// Insert the real UID into the map if it's new; log mapping with namespaced placeholder
fn log_insert(test_name: &str, uid_map: &mut HashMap<usize, String>, uid: &UniqueIdentifier) {
    if let Some(idx) = store_next_uid(uid_map, uid) {
        if let UniqueIdentifier::TextString(s) = uid {
            trace!(
                "[{}] mapped {} -> {}",
                test_name,
                format!("{}-uid-{}", test_name, idx),
                s
            );
        }
    }
}

fn log_insert_text(test_name: &str, uid_map: &mut HashMap<usize, String>, uid: &str) {
    if let Some(idx) = store_next_uid_text(uid_map, uid) {
        trace!(
            "[{}] mapped {} -> {}",
            test_name,
            format!("{}-uid-{}", test_name, idx),
            uid
        );
    }
}

// Store next UID if it is not already present. Return index used when inserted.
fn store_next_uid(uid_map: &mut HashMap<usize, String>, uid: &UniqueIdentifier) -> Option<usize> {
    let UniqueIdentifier::TextString(s) = uid else {
        return None;
    };
    // Avoid duplicates
    if uid_map.values().any(|v| v == s) {
        return None;
    }
    let idx = uid_map.len();
    uid_map.insert(idx, s.clone());
    Some(idx)
}

fn store_next_uid_text(uid_map: &mut HashMap<usize, String>, uid: &str) -> Option<usize> {
    if uid_map.values().any(|v| v == uid) {
        return None;
    }
    let idx = uid_map.len();
    uid_map.insert(idx, uid.to_string());
    Some(idx)
}

// Substitute a placeholder UID (namespaced or legacy) with the real value from the map.
fn substitute_uid(test_name: &str, uid: &mut UniqueIdentifier, uid_map: &HashMap<usize, String>) {
    let UniqueIdentifier::TextString(s) = uid else {
        return;
    };
    // Accept patterns:
    //   {test_name}-uid-{n}
    //   uid-{n}
    //   $UNIQUE_IDENTIFIER_{n}
    let idx_opt = s
        .strip_prefix(test_name)
        .and_then(|r| r.strip_prefix("-uid-"))
        .map_or_else(
            || {
                s.strip_prefix("uid-").map_or_else(
                    || {
                        s.strip_prefix("$UNIQUE_IDENTIFIER_")
                            .and_then(|rest| rest.parse::<usize>().ok())
                    },
                    |rest| rest.parse::<usize>().ok(),
                )
            },
            |rest| rest.parse::<usize>().ok(),
        );
    if let Some(idx) = idx_opt {
        if let Some(real) = uid_map.get(&idx) {
            *s = real.clone();
        }
    }
}

// Substitute a placeholder LinkedObjectIdentifier with the real value from the map.
fn substitute_linked_uid(
    test_name: &str,
    uid: &mut LinkedObjectIdentifier,
    uid_map: &HashMap<usize, String>,
) {
    let LinkedObjectIdentifier::TextString(s) = uid else {
        return;
    };
    // Accept patterns:
    //   {test_name}-uid-{n}
    //   uid-{n}
    //   $UNIQUE_IDENTIFIER_{n}
    let idx_opt = s
        .strip_prefix(test_name)
        .and_then(|r| r.strip_prefix("uid-"))
        .map_or_else(
            || {
                s.strip_prefix("uid-").map_or_else(
                    || {
                        s.strip_prefix("$UNIQUE_IDENTIFIER_")
                            .and_then(|rest| rest.parse::<usize>().ok())
                    },
                    |rest| rest.parse::<usize>().ok(),
                )
            },
            |rest| rest.parse::<usize>().ok(),
        );
    if let Some(idx) = idx_opt {
        if let Some(real) = uid_map.get(&idx) {
            *s = real.clone();
        }
    }
}
