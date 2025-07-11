use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyValue},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::{Object, ObjectType, SymmetricKey},
        kmip_operations::{Operation, Register},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use zeroize::Zeroizing;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_register_2_1() {
    // log_init(Some("debug"));
    log_init(option_env!("RUST_LOG"));

    let client = get_client();

    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_value: Some(KeyValue::ByteString(Zeroizing::new(vec![1, 2, 3, 4]))),
            key_compression_type: None,
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Register,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Register(Register {
                    object,
                    object_type: ObjectType::SymmetricKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        cryptographic_usage_mask: Some(
                            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                        ),
                        cryptographic_length: Some(256),
                        ..Default::default()
                    },
                    protection_storage_masks: None,
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V21 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));

    let Some(Operation::RegisterResponse(register_response)) = &batch_item.response_payload else {
        panic!("Expected RegisterResponse");
    };

    assert!(!register_response.unique_identifier.to_string().is_empty());
}
