use cosmian_kmip::kmip::{
    kmip_messages::{Message, MessageBatchItem, MessageHeader},
    kmip_operations::Operation,
    kmip_types::ProtocolVersion,
};

use crate::{KmsClient, KmsClientError};

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
    let request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            batch_count: operations.len() as u32,
            ..Default::default()
        },
        items: operations.into_iter().map(MessageBatchItem::new).collect(),
    };
    let response = kms_rest_client.message(request).await?;
    response
        .items
        .into_iter()
        .map(|item| {
            if let Some(payload) = item.response_payload {
                Ok(payload)
            } else {
                Err(format!(
                    "Error: {} {}",
                    item.result_reason.unwrap_or_default(),
                    item.result_message.unwrap_or_default()
                ))
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KmsClientError::Default(e.to_string()))
}
