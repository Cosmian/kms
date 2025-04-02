#![allow(unused)]
use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_0,
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned,
        },
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
    },
    kmip_1_4,
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
    log_init(Some("debug"));
    let request = hex::decode(DISCOVER_VERSIONS_1).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("request: {:#?}", ttlv);
    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    assert_eq!(
        request_message.request_payload,
        kmip_1_4::kmip_operations::Operation::DiscoverVersions(DiscoverVersions {
            protocol_version: None
        })
    );
    info!("request: {:#?}", request_message);

    // response
    let response = hex::decode(DISCOVER_VERSIONS_1_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    info!("response: {:#?}", ttlv);
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
        &kmip_1_4::kmip_operations::Operation::DiscoverVersionsResponse(DiscoverVersionsResponse {
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
    log_init(Some("debug"));
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
        kmip_1_4::kmip_operations::Operation::DiscoverVersions(DiscoverVersions {
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
    info!("response: {:#?}", response_message);
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
        &kmip_1_4::kmip_operations::Operation::DiscoverVersionsResponse(DiscoverVersionsResponse {
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
