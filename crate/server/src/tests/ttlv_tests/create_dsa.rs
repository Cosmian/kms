use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
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
fn test_create_dsa_private_key_2_1() {
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
                unique_batch_item_id: Some(b"dsa-test".to_vec()),
                request_payload: Operation::Create(Create {
                    object_type: ObjectType::PrivateKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::DSA),
                        cryptographic_length: Some(2048),
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
        .expect("Failed to send DSA create request");

    assert_eq!(response.batch_item.len(), 1, "Expected one batch item");
    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Missing batch item");
    };
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected KMIP 2.1 batch item");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "DSA create failed: reason={:?} message={:?}",
        batch_item.result_reason,
        batch_item.result_message
    );
    assert_eq!(batch_item.unique_batch_item_id, Some(b"dsa-test".to_vec()));
    let Some(Operation::CreateResponse(create_response)) = &batch_item.response_payload else {
        panic!("Expected CreateResponse");
    };
    assert_eq!(create_response.object_type, ObjectType::PrivateKey);
    assert!(
        !create_response.unique_identifier.to_string().is_empty(),
        "UID should not be empty"
    );
}
