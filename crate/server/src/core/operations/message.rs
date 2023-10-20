use cosmian_kmip::kmip::{
    kmip_messages::{RequestMessage, ResponseBatchItem, ResponseHeader, ResponseMessage},
    kmip_types::ResultStatusEnumeration,
    ttlv::serializer::to_ttlv,
};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use crate::{
    core::{operations::dispatch, KMS},
    result::KResult,
};

pub async fn message(
    kms: &KMS,
    request: RequestMessage,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ResponseMessage> {
    trace!("Entering message KMIP operation: {request:#?}");

    let mut response_items = Vec::new();
    for item_request in request.items {
        let operation = item_request.request_payload;
        let ttlv = to_ttlv(&operation)?;
        let operation = dispatch(kms, &ttlv, owner, params).await?;
        response_items.push(ResponseBatchItem {
            operation: Some(operation.operation_enum()),
            unique_batch_item_id: item_request.unique_batch_item_id,
            result_status: ResultStatusEnumeration::Success,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            response_payload: Some(operation),
            message_extension: None,
        });
    }

    let response_message = ResponseMessage {
        header: ResponseHeader {
            protocol_version: request.header.protocol_version,
            batch_count: 1,
            client_correlation_value: None,
            server_correlation_value: None,
            attestation_type: None,
            timestamp: 1697201574,
            nonce: None,
            server_hashed_password: None,
        },
        items: response_items,
    };

    Ok(response_message)
}
