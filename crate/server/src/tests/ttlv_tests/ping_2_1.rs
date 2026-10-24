use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Operation, Ping, PingResponse},
        kmip_types::OperationEnumeration,
    },
    ttlv::KmipFlavor,
};

use crate::tests::ttlv_tests::get_client;

/// KMIP 2.1 §6.1.36: Ping succeeds with an empty, but present, response payload.
#[test]
fn test_ping_2_1() {
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
                operation: OperationEnumeration::Ping,
                ephemeral: None,
                unique_batch_item_id: Some(b"ping".to_vec()),
                request_payload: Operation::Ping(Ping),
                message_extension: None,
            },
        )],
    };

    let response = get_client()
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
        .expect("Failed to send request");

    let [ResponseMessageBatchItemVersioned::V21(item)] = response.batch_item.as_slice() else {
        panic!("Expected one V21 response batch item");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(item.operation, Some(OperationEnumeration::Ping));
    assert_eq!(
        item.response_payload,
        Some(Operation::PingResponse(PingResponse))
    );
}
