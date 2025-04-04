#![allow(unused)]
use std::option;

use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_0::{
        self,
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned,
        },
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
    },
    kmip_1_4::{
        self,
        kmip_operations::{Operation, Query, QueryResponse},
    },
    ttlv::{from_ttlv, KmipFlavor, TTLV},
};

const DISCOVER_VERSIONS_1: &str = "42007801000000604200770100000038420069010000002042006a02000000040000000100000000\
42006b0200000004000000010000000042000d02000000040000000100000000\
42000f010000001842005c05000000040000001e000000004200790100000000";

const DISCOVER_VERSIONS_1_RESPONSE: &str = "42007b010000017042007a01000000484200690100000020\
42006a0200000004000000010000000042006b02000000040000000100000000\
42009209000000080000000067ea85f542000d02000000040000000100000000\
42000f010000011842005c05000000040000001e0000000042007f05000000040000000000000000\
42007c01000000f0420069010000002042006a0200000004000000020000000042006b02000000040000000000000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000400000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000300000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000200000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000100000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000000000000";

#[test]
fn discover_versions_1() {
    log_init(option_env!("RUST_LOG"));
    let request = hex::decode(DISCOVER_VERSIONS_1).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    assert_eq!(
        request_message.request_payload,
        Operation::DiscoverVersions(DiscoverVersions {
            protocol_version: None
        })
    );

    // response
    let response = hex::decode(DISCOVER_VERSIONS_1_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    let ResponseMessageBatchItemVersioned::V14(response_message) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &response_message.response_payload else {
        panic!("Expected response payload");
    };
    assert_eq!(
        response_payload,
        &Operation::DiscoverVersionsResponse(DiscoverVersionsResponse {
            protocol_version: Some(vec![
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 0
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 4
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 3
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 2
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 1
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 0
                }
            ])
        })
    );
}

const DISCOVER_VERSIONS_2: &str = "420078010000007042007701000000384200690100000020\
42006a0200000004000000010000000042006b0200000004000000010000000042000d02000000040000000100000000\
42000f010000002842005c05000000040000001e000000004200930800000008514c4b43010000004200790100000000";

const DISCOVER_VERSIONS_2_RESPONSE: &str = "42007b010000018042007a01000000484200690100000020\
42006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ea85f5\
42000d0200000004000000010000000042000f010000012842005c05000000040000001e00000000\
4200930800000008514c4b430100000042007f0500000004000000000000000042007c01000000f0\
420069010000002042006a0200000004000000020000000042006b02000000040000000000000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000400000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000300000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000200000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000100000000\
420069010000002042006a0200000004000000010000000042006b02000000040000000000000000";

#[test]
fn discover_versions_2() {
    log_init(option_env!("RUST_LOG"));
    let request = hex::decode(DISCOVER_VERSIONS_2).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    assert_eq!(
        request_message.request_payload,
        Operation::DiscoverVersions(DiscoverVersions {
            protocol_version: None
        })
    );

    // response
    let response = hex::decode(DISCOVER_VERSIONS_2_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    let ResponseMessageBatchItemVersioned::V14(response_message) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &response_message.response_payload else {
        panic!("Expected response payload");
    };
    assert!(request_message.unique_batch_item_id.is_some());
    assert_eq!(
        response_message.unique_batch_item_id,
        request_message.unique_batch_item_id
    );
    assert_eq!(
        response_payload,
        &Operation::DiscoverVersionsResponse(DiscoverVersionsResponse {
            protocol_version: Some(vec![
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 0
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 4
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 3
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 2
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 1
                },
                kmip_0::kmip_types::ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 0
                }
            ])
        })
    );
}

const QUERY: &str = "42007801000000804200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042000d0200000004000000010000000042000f010000003842005c050000000400000018000000004200930800000008514c4b4301000000420079010000001042007405000000040000000300000000";
const QUERY_RESPONSE: &str = "42007b01000000c042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ea85f542000d0200000004000000010000000042000f010000006842005c050000000400000018000000004200930800000008514c4b430100000042007f0500000004000000000000000042007c010000003042009d070000002250794b4d495020302e31312e302e6465763120536f66747761726520536572766572000000000000";

#[test]
fn query() {
    log_init(Some("debug"));
    let request = hex::decode(QUERY).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    info!("request_message: {:?}", request_message);
    assert_eq!(
        request_message.request_payload,
        Operation::Query(Query {
            query_function: Some(vec![
                kmip_1_4::kmip_types::QueryFunction::QueryServerInformation
            ]),
        })
    );

    // response
    let response = hex::decode(QUERY_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    let ResponseMessageBatchItemVersioned::V14(response_message) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &response_message.response_payload else {
        panic!("Expected response payload");
    };
    assert!(request_message.unique_batch_item_id.is_some());
    assert_eq!(
        response_message.unique_batch_item_id,
        request_message.unique_batch_item_id
    );
    info!("response_message: {:#?}", response_message);
    let Operation::QueryResponse(response_operation) = response_payload else {
        panic!("Expected QueryResponse");
    };
    assert_eq!(
        response_operation.vendor_identification,
        Some("PyKMIP 0.11.0.dev1 Software Server".to_owned())
    );
}

const CREATE: &str = "42007801000001304200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042000d0200000004000000010000000042000f01000000e842005c050000000400000001000000004200930800000008514c4b430100000042007901000000c04200570500000004000000020000000042009101000000a8420008010000003042000a070000001743727970746f6772617068696320416c676f726974686d0042000b05000000040000000300000000420008010000003042000a070000001843727970746f67726170686963205573616765204d61736b42000b02000000040000000c00000000420008010000003042000a070000001443727970746f67726170686963204c656e6774680000000042000b02000000040000010000000000";
const CREATE_RESPONSE: &str = "42007b01000000b042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ee614742000d0200000004000000010000000042000f010000005842005c050000000400000001000000004200930800000008514c4b430100000042007f0500000004000000000000000042007c01000000204200570500000004000000020000000042009407000000013100000000000000";

#[test]
fn create() {
    log_init(Some("debug"));
    let request = hex::decode(CREATE).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("ttlv: {:#?}", ttlv);

    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    info!("request_message: {:#?}", request_message);
    // assert_eq!(
    //     request_message.request_payload,
    //     Operation::Query(Query {
    //         query_function: Some(vec![
    //             kmip_1_4::kmip_types::QueryFunction::QueryServerInformation
    //         ]),
    //     })
    // );

    // response
    let response = hex::decode(CREATE_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    info!("response_message: {:#?}", response_message);

    let ResponseMessageBatchItemVersioned::V14(response_message) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &response_message.response_payload else {
        panic!("Expected response payload");
    };
    assert!(request_message.unique_batch_item_id.is_some());
    assert_eq!(
        response_message.unique_batch_item_id,
        request_message.unique_batch_item_id
    );
    // let Operation::QueryResponse(response_operation) = response_payload else {
    //     panic!("Expected QueryResponse");
    // };
    // assert_eq!(
    //     response_operation.vendor_identification,
    //     Some("PyKMIP 0.11.0.dev1 Software Server".to_owned())
    // );
}
