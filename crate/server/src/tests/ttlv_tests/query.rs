use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::ProtocolVersion,
    },
    kmip_1_4::{
        self,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, QueryFunction},
    },
    kmip_2_1,
    ttlv::KmipFlavor::Kmip1,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_query() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));
    test_query_(1, 2);
    test_query_(2, 1);
}
fn test_query_(major: i32, minor: i32) {
    let client = get_client();

    let query = Query {
        query_function: Some(vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
        ]),
    };
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(query),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: major,
            protocol_version_minor: minor,
        }
    );
    assert_eq!(response.batch_item.len(), 1);
    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    if major == 1 {
        let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
            panic!("Expected V14 request message");
        };
        let Some(kmip_1_4::kmip_operations::Operation::QueryResponse(query_response)) =
            &batch_item.response_payload
        else {
            panic!("Expected QueryResponse");
        };
        let Some(operations) = &query_response.operation else {
            panic!("Expected operations");
        };
        assert!(!operations.is_empty());
        let Some(object_types) = &query_response.object_type else {
            panic!("Expected object types");
        };
        assert!(!object_types.is_empty());
    } else {
        let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
            panic!("Expected V14 request message");
        };
        let Some(kmip_2_1::kmip_operations::Operation::QueryResponse(query_response)) =
            &batch_item.response_payload
        else {
            panic!("Expected QueryResponse");
        };
        let Some(operations) = &query_response.operation else {
            panic!("Expected operations");
        };
        assert!(!operations.is_empty());
        let Some(object_types) = &query_response.object_type else {
            panic!("Expected object types");
        };
        assert!(!object_types.is_empty());
    }
}
