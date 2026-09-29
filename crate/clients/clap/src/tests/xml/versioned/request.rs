//! Version-dispatched artifact extraction from KMIP responses.
//!
//! Provides `update_cached_artifacts_versioned` which iterates over all batch items
//! in a response, dispatching V14 and V21 items to version-specific logic.

use cosmian_kmip::{
    kmip_0::kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
    kmip_1_4::kmip_operations::Operation as Op14,
    kmip_2_1::{kmip_operations::Operation as Op21, kmip_types::UniqueIdentifier},
};

use crate::tests::xml::request::PrepareRequest;

/// Shared macro for extracting cached artifacts from response payloads.
///
/// Handles fields common to all KMIP versions (encrypt, decrypt, sign, MAC)
/// plus a version-specific `uid:` arm for UID extraction.
macro_rules! update_artifacts_from_payload {
    ($state:expr, $pending_aad:expr, $op:ident, $payload:expr, uid: $($uid_arms:tt)*) => {
        // Encrypt artifacts
        if let Some($op::EncryptResponse(enc_resp)) = $payload {
            match (&enc_resp.data, &enc_resp.i_v_counter_nonce) {
                (Some(data), Some(iv)) => {
                    let tag: Vec<u8> = enc_resp
                        .authenticated_encryption_tag
                        .clone()
                        .unwrap_or_default();
                    $state.last_encrypt_artifacts =
                        Some((data.clone(), iv.clone(), tag.clone()));
                    if let Some(aad) = $pending_aad.take() {
                        $state
                            .encrypt_artifacts_by_aad
                            .insert(aad, (data.clone(), iv.clone(), tag.clone()));
                    }
                }
                _ => $state.last_encrypt_artifacts = None,
            }
        }
        if let Some($op::DecryptResponse(_)) = $payload {
            $state.last_encrypt_artifacts = None;
        }
        if let Some($op::SignResponse(sr)) = $payload {
            $state.last_signature_from_sign = sr.signature_data.clone().into();
        }
        if let Some($op::MACResponse(mr)) = $payload {
            $state.last_mac_from_mac = mr.mac_data.clone();
        }
        // UID extraction (version-specific)
        match $payload {
            $($uid_arms)*
            _ => {}
        }
    };
}

/// Update cached artifacts from all batch items in a response for subsequent requests.
///
/// Iterates through all batch items and dispatches to V14 or V21 logic.
pub(crate) fn update_cached_artifacts_versioned(
    state: &mut PrepareRequest,
    resp: &ResponseMessage,
    pending_encrypt_aad: &mut Option<Vec<u8>>,
) {
    for bi in &resp.batch_item {
        match bi {
            ResponseMessageBatchItemVersioned::V21(inner) => {
                update_artifacts_from_payload!(
                    state, pending_encrypt_aad, Op21, &inner.response_payload,
                    uid:
                    Some(Op21::CreateResponse(cr)) => {
                        if let UniqueIdentifier::TextString(s) = &cr.unique_identifier {
                            state.last_uid = Some(s.clone());
                        }
                    }
                    Some(Op21::PKCS11Response(pk)) => {
                        state.last_pkcs11_correlation_value = pk.correlation_value.clone();
                    }
                    Some(Op21::RegisterResponse(rr)) => {
                        if let UniqueIdentifier::TextString(s) = &rr.unique_identifier {
                            state.last_uid = Some(s.clone());
                        }
                    }
                    Some(Op21::CreateKeyPairResponse(ckpr)) => {
                        if let UniqueIdentifier::TextString(s) = &ckpr.private_key_unique_identifier {
                            state.last_uid = Some(s.clone());
                        }
                    }
                    Some(Op21::LocateResponse(lr)) => {
                        if let Some(list) = &lr.unique_identifier {
                            if list.len() == 1 {
                                if let UniqueIdentifier::TextString(s) = &list[0] {
                                    state.last_uid = Some(s.clone());
                                }
                            }
                        }
                    }
                );
            }
            ResponseMessageBatchItemVersioned::V14(inner) => {
                update_artifacts_from_payload!(
                    state, pending_encrypt_aad, Op14, &inner.response_payload,
                    uid:
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
                );
            }
        }
    }
}
