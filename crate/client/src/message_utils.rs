use cosmian_kmip::kmip::{
    kmip_messages::{Message, MessageBatchItem, MessageHeader},
    kmip_operations::Operation,
    kmip_types::ProtocolVersion,
};

use crate::{ClientError, KmsRestClient};

pub async fn batch_operations(
    kms_rest_client: &KmsRestClient,
    operations: Vec<Operation>,
) -> Result<Vec<Option<Operation>>, ClientError> {
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
        items: operations
            .into_iter()
            .map(|op| MessageBatchItem::new(op))
            .collect(),
    };
    let response = kms_rest_client.message(request).await?;
    Ok(response
        .items
        .into_iter()
        .map(|item| item.response_payload)
        .collect())
}
