use cosmian_kmip::{
    kmip_0::kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
    kmip_2_1::{kmip_operations::Operation, kmip_types::UniqueIdentifier},
};

use crate::tests::kms::xml::request::PrepareRequest;

/// Update cached artifacts for KMIP 2.1 responses only.
pub(crate) fn update_cached_artifacts_v21(
    state: &mut PrepareRequest,
    resp: &ResponseMessage,
    pending_encrypt_aad: &mut Option<Vec<u8>>,
) {
    for bi in &resp.batch_item {
        let ResponseMessageBatchItemVersioned::V21(inner) = bi else {
            continue;
        };

        if let Some(Operation::EncryptResponse(enc_resp)) = &inner.response_payload {
            match (&enc_resp.data, &enc_resp.i_v_counter_nonce) {
                (Some(data), Some(iv)) => {
                    let tag: Vec<u8> = enc_resp
                        .authenticated_encryption_tag
                        .clone()
                        .unwrap_or_default();
                    state.last_encrypt_artifacts = Some((data.clone(), iv.clone(), tag.clone()));
                    if let Some(aad) = pending_encrypt_aad.take() {
                        state
                            .encrypt_artifacts_by_aad
                            .insert(aad, (data.clone(), iv.clone(), tag.clone()));
                    }
                }
                _ => {
                    state.last_encrypt_artifacts = None;
                }
            }
        }
        if let Some(Operation::DecryptResponse(_)) = &inner.response_payload {
            state.last_encrypt_artifacts = None;
        }
        if let Some(Operation::SignResponse(sr)) = &inner.response_payload {
            state.last_signature_from_sign = sr.signature_data.clone();
        }
        if let Some(Operation::MACResponse(mr)) = &inner.response_payload {
            state.last_mac_from_mac = mr.mac_data.clone();
        }

        // Update last_uid and PKCS11 correlation from response payloads
        match &inner.response_payload {
            Some(Operation::CreateResponse(cr)) => {
                if let UniqueIdentifier::TextString(s) = &cr.unique_identifier {
                    state.last_uid = Some(s.clone());
                }
            }
            Some(Operation::PKCS11Response(pk)) => {
                state.last_pkcs11_correlation_value = pk.correlation_value.clone();
            }
            Some(Operation::RegisterResponse(rr)) => {
                if let UniqueIdentifier::TextString(s) = &rr.unique_identifier {
                    state.last_uid = Some(s.clone());
                }
            }
            Some(Operation::CreateKeyPairResponse(ckpr)) => {
                if let UniqueIdentifier::TextString(s) = &ckpr.private_key_unique_identifier {
                    state.last_uid = Some(s.clone());
                }
            }
            Some(Operation::LocateResponse(lr)) => {
                if let Some(list) = &lr.unique_identifier {
                    if list.len() == 1 {
                        if let UniqueIdentifier::TextString(s) = &list[0] {
                            state.last_uid = Some(s.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
