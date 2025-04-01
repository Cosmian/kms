use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned, ResponseMessageHeader,
        },
        kmip_types::{ErrorReason, ResultStatusEnumeration},
    },
    kmip_2_1::kmip_messages::ResponseMessageBatchItem,
    ttlv::to_ttlv,
};
use cosmian_kms_interfaces::SessionParams;
use tracing::trace;

use crate::{
    core::{operations::dispatch, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Processing of an input KMIP Message
///
/// Process every item from the message request.
/// Each batch item contains an operation to process.
///
/// The items are processed sequentially.
/// Each item may fail, but a response is still sent back.
pub(crate) async fn message(
    kms: &KMS,
    request: RequestMessage,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ResponseMessage> {
    trace!("Entering message KMIP operation: {request:?}");

    let mut response_items = Vec::new();
    for versioned_batch_item in request.batch_item {
        let batch_item = match versioned_batch_item {
            // RequestMessageBatchItemVersioned::V14(item_request) => {
            //     kmip_2_1::kmip_messages::RequestMessageBatchItem::from(item_request)
            // }
            RequestMessageBatchItemVersioned::V21(item_request) => item_request,
            RequestMessageBatchItemVersioned::V14(_item_request) => {
                kms_bail!("Need to implement conversion for V14 to V21");
            }
        };

        let operation = batch_item.request_payload;
        // conversion for `dispatch` call convenience
        let ttlv = to_ttlv(&operation)?;

        let (result_status, result_reason, result_message, response_payload) =
            match dispatch(kms, ttlv, owner, params.clone()).await {
                Ok(operation) => (
                    ResultStatusEnumeration::Success,
                    None,
                    None,
                    Some(operation),
                ),
                Err(KmsError::Kmip21Error(reason, error_message)) => (
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

        response_items.push(ResponseMessageBatchItemVersioned::V21(
            ResponseMessageBatchItem {
                operation: Some(batch_item.operation),
                unique_batch_item_id: batch_item.unique_batch_item_id,
                result_status,
                result_reason,
                result_message,
                asynchronous_correlation_value: None,
                response_payload,
                message_extension: None,
            },
        ));
    }

    let response_message = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: request.request_header.protocol_version,
            batch_count: i32::try_from(response_items.len())?,
            client_correlation_value: None,
            server_correlation_value: None,
            attestation_type: None,
            time_stamp: chrono::Utc::now().timestamp(),
            nonce: None,
            server_hashed_password: None,
        },
        batch_item: response_items,
    };

    Ok(response_message)
}
