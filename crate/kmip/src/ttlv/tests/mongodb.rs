#![allow(unused)]
use std::option;

use cosmian_logger::log_init;
use tracing::info;
use zeroize::Zeroizing;

use crate::{
    kmip_0::{
        self,
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned,
        },
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
        kmip_types::CryptographicUsageMask,
    },
    kmip_1_4::{
        self,
        kmip_attributes::{Attribute, CustomAttributeValue},
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, TemplateAttribute},
        kmip_objects::{Object, SymmetricKey},
        kmip_operations::{
            AddAttribute, Create, CreateResponse, Get, GetAttributes, GetAttributesResponse,
            GetResponse, Operation, Query, QueryResponse, Register,
        },
        kmip_types::{CryptographicAlgorithm, KeyFormatType, ObjectType},
    },
    ttlv::{from_ttlv, KmipFlavor, TTLV},
};

const REGISTER: &str = "42007801000001504200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000000000000042000d0200000004000000010000000042000f010000010842005c0500000004000000030000000042007901000000f0420057050000000400000007000000004200910100000038420008010000003042000a070000001843727970746f67726170686963205573616765204d61736b42000b0200000004000000000000000042008501000000984200860500000004000000020000000042004001000000804200420500000004000000020000000042004501000000684200430800000060171d58326d87fd04daa8c6d404ef8d47a7b93d9e414ec0926b0572ed3bdb92530e3c7a6fe567ba425df6fefdb44de070be3a64df24affcaa07e2b2212c135beb1bf7c44eb2aa801ffefee013574e71fadfbbdbd9b5607d6d8a90c38ba899269c";

#[test]
fn register() {
    log_init(Some("info"));
    // log_init(option_env!("RUST_LOG"));
    let request = hex::decode(REGISTER).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 0);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("TTLV: {ttlv:#?}");
    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    info!("REQUEST MESSAGE: {request_message:#?}");
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    let Operation::Register(register) = &request_message.request_payload else {
        panic!("Expected Register operation");
    };
    assert_eq!(register.object.object_type(), ObjectType::SecretData);
    assert_eq!(
        register.template_attribute,
        Some(TemplateAttribute {
            attribute: Some(vec![Attribute::CryptographicUsageMask(
                CryptographicUsageMask(0)
            )])
        })
    );

    // // response
    // let response = hex::decode(DISCOVER_VERSIONS_1_RESPONSE).unwrap();
    // let (major, minor) = TTLV::find_version(&response).unwrap();
    // assert_eq!(major, 1);
    // assert_eq!(minor, 1);
    // let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    // let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    // let ResponseMessageBatchItemVersioned::V14(response_message) = &response_message.batch_item[0]
    // else {
    //     panic!("Expected V14 response message");
    // };
    // let Some(response_payload) = &response_message.response_payload else {
    //     panic!("Expected response payload");
    // };
    // assert_eq!(
    //     response_payload,
    //     &Operation::DiscoverVersionsResponse(DiscoverVersionsResponse {
    //         protocol_version: Some(vec![
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 2,
    //                 protocol_version_minor: 0
    //             },
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 1,
    //                 protocol_version_minor: 4
    //             },
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 1,
    //                 protocol_version_minor: 3
    //             },
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 1,
    //                 protocol_version_minor: 2
    //             },
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 1,
    //                 protocol_version_minor: 1
    //             },
    //             kmip_0::kmip_types::ProtocolVersion {
    //                 protocol_version_major: 1,
    //                 protocol_version_minor: 0
    //             }
    //         ])
    //     })
    // );
}
