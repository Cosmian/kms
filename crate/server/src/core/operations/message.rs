use cosmian_kmip::kmip::{
    kmip_messages::{Message, MessageResponse, MessageResponseBatchItem, MessageResponseHeader},
    kmip_operations::ErrorReason,
    kmip_types::ResultStatusEnumeration,
    ttlv::serializer::to_ttlv,
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::trace;

use crate::{
    core::{operations::dispatch, KMS},
    error::KmsError,
    result::KResult,
};

/// Processing of an input KMIP Message
///
/// Process every item from the message request.
/// Each batch item contains an operation to process.
///
/// The items are processed sequentially.
/// Each item may fail but a response is still sent back.
pub(crate) async fn message(
    kms: &KMS,
    request: Message,
    owner: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<MessageResponse> {
    trace!("Entering message KMIP operation: {request}");

    let mut response_items = Vec::new();
    for item_request in request.items {
        let operation = item_request.request_payload;
        // conversion for `dispatch` call convenience
        let ttlv = to_ttlv(&operation)?;

        #[allow(clippy::large_futures)]
        let (result_status, result_reason, result_message, response_payload) =
            match dispatch(kms, &ttlv, owner, params).await {
                Ok(operation) => (
                    ResultStatusEnumeration::Success,
                    None,
                    None,
                    Some(operation),
                ),
                Err(KmsError::KmipError(reason, error_message)) => (
                    ResultStatusEnumeration::OperationFailed,
                    Some(reason),
                    Some(error_message),
                    None,
                ),
                Err(err) => (
                    ResultStatusEnumeration::OperationFailed,
                    Some(ErrorReason::Operation_Not_Supported),
                    Some(err.to_string()),
                    None,
                ),
            };

        response_items.push(MessageResponseBatchItem {
            operation: Some(item_request.operation),
            unique_batch_item_id: item_request.unique_batch_item_id,
            result_status,
            result_reason,
            result_message,
            asynchronous_correlation_value: None,
            response_payload,
            message_extension: None,
        });
    }

    let response_message = MessageResponse {
        header: MessageResponseHeader {
            protocol_version: request.header.protocol_version,
            batch_count: u32::try_from(response_items.len())?,
            client_correlation_value: None,
            server_correlation_value: None,
            attestation_type: None,
            timestamp: u64::try_from(chrono::Utc::now().timestamp())?,
            nonce: None,
            server_hashed_password: None,
        },
        items: response_items,
    };

    Ok(response_message)
}
