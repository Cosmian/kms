use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4, kmip_2_1,
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_query() {
    log_init(option_env!("RUST_LOG"));
    test_query_(1, 2);
    info!("Test KMIP 1 ==> OK");
    test_query_(2, 1);
    info!("Test KMIP 2 ==> OK");
}
fn test_query_(major: i32, minor: i32) {
    let client = get_client();

    let mut request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![],
    };
    if major == 1 {
        request_message
            .batch_item
            .push(RequestMessageBatchItemVersioned::V14(
                kmip_1_4::kmip_messages::RequestMessageBatchItem {
                    operation: kmip_1_4::kmip_types::OperationEnumeration::Query,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: kmip_1_4::kmip_operations::Operation::Query(
                        kmip_1_4::kmip_operations::Query {
                            query_function: Some(vec![
                                kmip_1_4::kmip_types::QueryFunction::QueryOperations,
                                kmip_1_4::kmip_types::QueryFunction::QueryObjects,
                                kmip_1_4::kmip_types::QueryFunction::QueryServerInformation,
                            ]),
                        },
                    ),
                    message_extension: None,
                },
            ));
    } else {
        request_message
            .batch_item
            .push(RequestMessageBatchItemVersioned::V21(
                kmip_2_1::kmip_messages::RequestMessageBatchItem {
                    operation: kmip_2_1::kmip_types::OperationEnumeration::Query,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: kmip_2_1::kmip_operations::Operation::Query(
                        kmip_2_1::kmip_operations::Query {
                            query_function: Some(vec![
                                kmip_2_1::kmip_types::QueryFunction::QueryOperations,
                                kmip_2_1::kmip_types::QueryFunction::QueryObjects,
                                kmip_2_1::kmip_types::QueryFunction::QueryServerInformation,
                            ]),
                            ..Default::default()
                        },
                    ),
                    message_extension: None,
                },
            ));
    }

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(
            if major == 1 {
                KmipFlavor::Kmip1
            } else {
                KmipFlavor::Kmip2
            },
            &request_message,
        )
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
        assert_ne!(operations.as_slice(), []);
        let Some(object_types) = &query_response.object_type else {
            panic!("Expected object types");
        };
        assert_ne!(object_types.as_slice(), []);
        let Some(vendor_identification) = &query_response.vendor_identification else {
            panic!("Expected vendor identification");
        };
        assert!(!vendor_identification.is_empty());
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
        assert_ne!(operations.as_slice(), []);
        let Some(object_types) = &query_response.object_type else {
            panic!("Expected object types");
        };
        assert_ne!(object_types.as_slice(), []);
        let Some(vendor_identification) = &query_response.vendor_identification else {
            panic!("Expected vendor identification");
        };
        assert!(!vendor_identification.is_empty());
    }
}

#[test]
fn test_query_rngs_and_server_information_2_1_binary() {
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
            kmip_2_1::kmip_messages::RequestMessageBatchItem {
                operation: kmip_2_1::kmip_types::OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: kmip_2_1::kmip_operations::Operation::Query(
                    kmip_2_1::kmip_operations::Query {
                        query_function: Some(vec![
                            kmip_2_1::kmip_types::QueryFunction::QueryRNGs,
                            kmip_2_1::kmip_types::QueryFunction::QueryServerInformation,
                        ]),
                        ..Default::default()
                    },
                ),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
        .expect("Failed to send Query request");

    assert_eq!(response.batch_item.len(), 1);
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("Expected KMIP 2.1 response");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(kmip_2_1::kmip_operations::Operation::QueryResponse(query_response)) =
        &batch_item.response_payload
    else {
        panic!("Expected QueryResponse");
    };
    assert_eq!(
        query_response.rng_parameters.as_ref().map(Vec::len),
        Some(1)
    );
}
