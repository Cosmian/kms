use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_2_1::kmip_operations::Operation,
};

use crate::{
    KmsClient, KmsClientError,
    cosmian_kmip::kmip_0::kmip_messages::ResponseMessageBatchItemVersioned,
    kmip_2_1::kmip_messages::RequestMessageBatchItem,
};

/// Uses the KMIP Message interface to send a batch of operations to the KMS.
/// The operations are sent in a single request and the response is a list of results.
/// The operations are executed in the order they are provided.
/// The response list contains the results in the same order as the operations.
/// If the operation was successful, the result is the response payload.
/// If the operation failed, the result is an error message.
/// The response list is guaranteed to have the same length as the operations list.
pub(crate) async fn batch_operations(
    kms_rest_client: &KmsClient,
    operations: Vec<Operation>,
) -> Result<Vec<Operation>, KmsClientError> {
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            batch_count: i32::try_from(operations.len())?,
            ..Default::default()
        },
        batch_item: operations
            .into_iter()
            .map(|op| RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(op)))
            .collect(),
    };
    let response = kms_rest_client.message(request).await?;
    response
        .batch_item
        .into_iter()
        .map(|item| {
            let ResponseMessageBatchItemVersioned::V21(item) = item else {
                return Err(KmsClientError::Default("Invalid response".to_string()));
            };
            if let Some(payload) = item.response_payload {
                Ok(payload)
            } else {
                Err(KmsClientError::Default(format!(
                    "Error: {} {}",
                    item.result_reason.unwrap_or_default(),
                    item.result_message.unwrap_or_default()
                )))
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}
