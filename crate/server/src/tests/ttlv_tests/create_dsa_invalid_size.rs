use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ErrorReason, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Operation},
        kmip_types::{CryptographicAlgorithm, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_create_dsa_invalid_size() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();
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
                operation: OperationEnumeration::Create,
                ephemeral: None,
                unique_batch_item_id: Some(b"dsa-invalid".to_vec()),
                request_payload: Operation::Create(Create {
                    object_type: ObjectType::PrivateKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::DSA),
                        cryptographic_length: Some(400),
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
        .expect("Failed to send DSA create invalid request");
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("Expected 2.1 batch item");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed,
        "Expected OperationFailed for invalid size"
    );
    assert_eq!(
        batch_item.result_reason,
        Some(ErrorReason::Operation_Not_Supported),
        "Expected Not Supported reason"
    );
}
