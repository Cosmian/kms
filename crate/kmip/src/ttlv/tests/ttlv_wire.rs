use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_2_1,
    kmip_2_1::{
        kmip_messages::{RequestMessageBatchItem, RequestMessageHeader},
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, ProtocolVersion, QueryFunction},
        RequestMessage,
    },
    ttlv::{from_ttlv, to_ttlv, TTLVBytesDeserializer, TTLVBytesSerializer},
};

#[test]
fn test_serialization_deserialization() {
    log_init(Some("trace"));
    // KMIP Request Message in Rust
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            maximum_response_size: Some(256),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItem {
            operation: OperationEnumeration::Query,
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: Operation::Query(Query {
                query_function: Some(vec![
                    QueryFunction::QueryOperations,
                    QueryFunction::QueryObjects,
                ]),
            }),
            message_extension: None,
        }],
    };

    // Serializer
    let ttlv = to_ttlv(&request_message).unwrap();

    // Bytes serializer
    let mut buffer = Vec::new();
    TTLVBytesSerializer::new(&mut buffer)
        .write_ttlv::<kmip_2_1::kmip_types::Tag>(&ttlv)
        .unwrap();

    // Byte deserializer
    let (ttlv_, length) = TTLVBytesDeserializer::new(buffer.as_slice())
        .read_ttlv::<kmip_2_1::kmip_types::Tag>()
        .unwrap();
    // Assert that the length of the deserialized TTLV matches the original
    assert_eq!(length, buffer.len());
    // Assert that the deserialized TTLV matches the original
    assert_eq!(ttlv_, ttlv);
    info!("ttlv: {:#?}", ttlv_);
    // Deserialize the TTLV back to a RequestMessage
    let request_message_: RequestMessage = from_ttlv(ttlv_).unwrap();
    // Assert that the original and deserialized messages are equal
    assert_eq!(request_message_, request_message);
}
