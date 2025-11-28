use cosmian_kmip::{
    kmip_0::kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
    kmip_1_4::kmip_operations::Operation as Op14,
};

use crate::tests::kms::xml::request::PrepareRequest;

/// Update cached artifacts for KMIP 1.4 responses only.
pub(crate) fn update_cached_artifacts_v14(
    state: &mut PrepareRequest,
    resp: &ResponseMessage,
    pending_encrypt_aad: &mut Option<Vec<u8>>,
) {
    for bi in &resp.batch_item {
        let ResponseMessageBatchItemVersioned::V14(inner) = bi else {
            continue;
        };

        match &inner.response_payload {
            Some(Op14::EncryptResponse(enc_resp)) => {
                match (&enc_resp.data, &enc_resp.i_v_counter_nonce) {
                    (Some(data), Some(iv)) => {
                        let tag: Vec<u8> = enc_resp
                            .authenticated_encryption_tag
                            .clone()
                            .unwrap_or_default();
                        state.last_encrypt_artifacts =
                            Some((data.clone(), iv.clone(), tag.clone()));
                        if let Some(aad) = pending_encrypt_aad.take() {
                            state
                                .encrypt_artifacts_by_aad
                                .insert(aad, (data.clone(), iv.clone(), tag.clone()));
                        }
                    }
                    _ => state.last_encrypt_artifacts = None,
                }
            }
            Some(Op14::DecryptResponse(_)) => {
                state.last_encrypt_artifacts = None;
            }
            Some(Op14::SignResponse(sr)) => {
                state.last_signature_from_sign = Some(sr.signature_data.clone());
            }
            Some(Op14::MACResponse(mr)) => {
                state.last_mac_from_mac = mr.mac_data.clone();
            }
            Some(Op14::CreateResponse(cr)) => {
                state.last_uid = Some(cr.unique_identifier.clone());
            }
            Some(Op14::RegisterResponse(rr)) => {
                state.last_uid = Some(rr.unique_identifier.clone());
            }
            Some(Op14::CreateKeyPairResponse(ckpr)) => {
                state.last_uid = Some(ckpr.private_key_unique_identifier.clone());
            }
            Some(Op14::LocateResponse(lr)) => {
                if let Some(list) = &lr.unique_identifier {
                    if list.len() == 1 {
                        state.last_uid = Some(list[0].clone());
                    }
                }
            }
            _ => {}
        }
    }
}
