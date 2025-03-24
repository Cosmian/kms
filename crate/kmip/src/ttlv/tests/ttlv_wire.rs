use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_1_4,
    kmip_2_1::{
        self,
        kmip_messages::{RequestMessageBatchItem, RequestMessageHeader},
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, ProtocolVersion, QueryFunction},
        RequestMessage,
    },
    ttlv::{from_ttlv, to_ttlv, TTLVBytesDeserializer, TTLVBytesSerializer, TTLV},
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

#[test]
fn test_pykmip_response_message_1_4() {
    log_init(option_env!("RUST_LOG"));
    let response = hex::decode("42007b01000001a042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000040000000042009209000000080000000067ddb66c42000d0200000004000000010000000042000f010000014842005c0500000004000000180000000042007f0500000004000000000000000042007c010000012042005c0500000004000000010000000042005c0500000004000000020000000042005c0500000004000000030000000042005c0500000004000000050000000042005c0500000004000000080000000042005c05000000040000000a0000000042005c05000000040000000b0000000042005c05000000040000000c0000000042005c0500000004000000120000000042005c0500000004000000130000000042005c0500000004000000140000000042005c0500000004000000180000000042005c05000000040000001e0000000042005c05000000040000001f0000000042005c0500000004000000200000000042005c0500000004000000210000000042005c0500000004000000220000000042005c05000000040000002300000000").unwrap();
    let ttlv = TTLV::from_bytes_1_4(&response).unwrap();
    let response_message: kmip_1_4::kmip_messages::ResponseMessage = from_ttlv(ttlv).unwrap();
    let response_message_ = kmip_1_4::kmip_messages::ResponseMessage {
        response_header: kmip_1_4::kmip_messages::ResponseMessageHeader {
            protocol_version: kmip_1_4::kmip_types::ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            time_stamp: 1_742_583_404_i64,
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![kmip_1_4::kmip_messages::ResponseMessageBatchItem {
            response_payload: Some(kmip_1_4::kmip_operations::Operation::QueryResponse(
                kmip_1_4::kmip_operations::QueryResponse {
                    operation: Some(vec![
                        kmip_1_4::kmip_types::OperationEnumeration::Create,
                        kmip_1_4::kmip_types::OperationEnumeration::CreateKeyPair,
                        kmip_1_4::kmip_types::OperationEnumeration::Register,
                        kmip_1_4::kmip_types::OperationEnumeration::DeriveKey,
                        kmip_1_4::kmip_types::OperationEnumeration::Locate,
                        kmip_1_4::kmip_types::OperationEnumeration::Get,
                        kmip_1_4::kmip_types::OperationEnumeration::GetAttributes,
                        kmip_1_4::kmip_types::OperationEnumeration::GetAttributeList,
                        kmip_1_4::kmip_types::OperationEnumeration::Activate,
                        kmip_1_4::kmip_types::OperationEnumeration::Revoke,
                        kmip_1_4::kmip_types::OperationEnumeration::Destroy,
                        kmip_1_4::kmip_types::OperationEnumeration::Query,
                        kmip_1_4::kmip_types::OperationEnumeration::DiscoverVersions,
                        kmip_1_4::kmip_types::OperationEnumeration::Encrypt,
                        kmip_1_4::kmip_types::OperationEnumeration::Decrypt,
                        kmip_1_4::kmip_types::OperationEnumeration::Sign,
                        kmip_1_4::kmip_types::OperationEnumeration::SignatureVerify,
                        kmip_1_4::kmip_types::OperationEnumeration::MAC,
                    ]),
                    object_type: None,
                    vendor_identification: None,
                    server_information: None,
                    extension_information: None,
                    attestation_types: None,
                    rng_parameters: None,
                    profiles_information: None,
                    validation_information: None,
                    capability_information: None,
                    client_registration_method: None,
                },
            )),
            message_extension: None,
            operation: Some(kmip_1_4::kmip_types::OperationEnumeration::Query),
            unique_batch_item_id: None,
            result_status: kmip_1_4::kmip_types::ResultStatusEnumeration::Success,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
        }],
    };
    assert_eq!(response_message, response_message_);
}
