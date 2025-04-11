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
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse}, kmip_types::CryptographicUsageMask,
    },
    kmip_1_4::{
        self,
        kmip_attributes::{Attribute, CustomAttributeValue},
        kmip_data_structures::TemplateAttribute,
        kmip_operations::{AddAttribute, Create, CreateResponse, GetAttributes, GetAttributesResponse, Operation, Query, QueryResponse},
        kmip_types::{CryptographicAlgorithm,  KeyFormatType, ObjectType},
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
const QUERY: &str = 
    "42007801000000804200770100000038420069010000002042006a0200000004000000010000000042006b\
    0200000004000000010000000042000d0200000004000000010000000042000f010000003842005c050000\
    000400000018000000004200930800000008514c4b4301000000420079010000001042007405000000040000000300000000";

const QUERY_RESPONSE: &str = 
    "42007b01000000c042007a0100000048420069010000002042006a0200000004000000010000000042006b\
    0200000004000000010000000042009209000000080000000067ea85f542000d02000000040000000100000000\
    42000f010000006842005c050000000400000018000000004200930800000008514c4b430100000042007f0500\
    000004000000000000000042007c010000003042009d070000002250794b4d495020302e31312e302e6465763120\
    536f66747761726520536572766572000000000000";

#[test]
fn query() {
    log_init(option_env!("RUST_LOG"));
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
const CREATE: &str = 
    "420078010000013042007701000000384200690100000020\
    42006a0200000004000000010000000042006b0200000004000000010000000042000d02000000040000000100000000\
    42000f01000000e842005c050000000400000001000000004200930800000008514c4b430100000042007901000000c0\
    4200570500000004000000020000000042009101000000a8420008010000003042000a070000001743727970746f6772\
    617068696320416c676f726974686d0042000b05000000040000000300000000420008010000003042000a07000000\
    1843727970746f67726170686963205573616765204d61736b42000b02000000040000000c00000000420008010000\
    003042000a070000001443727970746f67726170686963204c656e6774680000000042000b0200000004000001000\
    0000000";

const CREATE_RESPONSE: &str = 
    "42007b01000000b042007a0100000048420069010000002042006a0200000004000000010000000042006b02000000\
    040000000100000000420092090000000800000000\
    67ee614742000d0200000004000000010000000042000f010000005842005c0500000004000000010000000042009308\
    00000008514c4b430100000042007f0500000004000000000000000042007c01000000204200570500000004000000\
    020000000042009407000000013100000000000000";

#[test]
fn create() {
    log_init(option_env!("RUST_LOG"));
    let request = hex::decode(CREATE).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("request ttlv: {:#?}", ttlv);

    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    info!("request_message: {:#?}", request_message);
    assert_eq!(
        request_message.request_payload,
        Operation::Create(Create {
            object_type: ObjectType::SymmetricKey,
            template_attribute: TemplateAttribute {
                attribute: Some(vec![
                    Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                    Attribute::CryptographicUsageMask(
                        CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt
                    ),
                    Attribute::CryptographicLength(256),
                ]),
            }
        })
    );

    // response
    let response = hex::decode(CREATE_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    info!("response ttlv: {:#?}", ttlv);

    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    info!("response_message: {:#?}", response_message);

    let ResponseMessageBatchItemVersioned::V14(batch_item) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &batch_item.response_payload else {
        panic!("Expected response payload");
    };
    assert!(request_message.unique_batch_item_id.is_some());
    assert_eq!(
        batch_item.unique_batch_item_id,
        request_message.unique_batch_item_id
    );
    assert_eq!(
        response_payload,
        &Operation::CreateResponse(CreateResponse {
            object_type: ObjectType::SymmetricKey,
            unique_identifier: "1".to_owned(),
            template_attribute: None
        })
    );
}


const GET_ATTRIBUTES: &str = "42007801000000a04200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042000d0200000004000000010000000042000f010000005842005c05000000040000000b000000004200930800000008514c4b430100000042007901000000304200940700000001310000000000000042000a0700000011782d50726f647563745f56657273696f6e00000000000000";
// const GET_ATTRIBUTES_RESPONSE: &str = "42007b01000000a042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ee614842000d0200000004000000010000000042000f010000004842005c05000000040000000b000000004200930800000008514c4b430100000042007f0500000004000000000000000042007c010000001042009407000000013100000000000000";
const GET_ATTRIBUTES_RESPONSE: &str = "42007b01000000a042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ee614842000d0200000004000000010000000042000f010000004842005c05000000040000000b000000004200930800000008514c4b430100000042007f0500000004000000000000000042007c010000001042009407000000013100000000000000";

#[test]
fn get_attributes() {
    log_init(Some("debug"));
    // log_init(option_env!("RUST_LOG"));
    let request = hex::decode(GET_ATTRIBUTES).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("request ttlv: {:#?}", ttlv);

    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V14(request_message) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    info!("request_message: {:#?}", request_message);
    assert_eq!(
        request_message.request_payload,
        Operation::GetAttributes(GetAttributes {
            unique_identifier: "1".to_owned(),
            attribute_name: Some(vec!["x-Product_Version". to_owned()]),
        })
    );

    // response
    let response = hex::decode(GET_ATTRIBUTES_RESPONSE).unwrap();
    let (major, minor) = TTLV::find_version(&response).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);
    let ttlv = TTLV::from_bytes(&response, KmipFlavor::Kmip1).unwrap();
    info!("response ttlv: {:#?}", ttlv);
    let response_message: ResponseMessage = from_ttlv(ttlv).unwrap();
    info!("response_message: {:#?}", response_message);
    let ResponseMessageBatchItemVersioned::V14(batch_item) = &response_message.batch_item[0]
    else {
        panic!("Expected V14 response message");
    };
    let Some(response_payload) = &batch_item.response_payload else {
        panic!("Expected response payload");
    };
    assert!(request_message.unique_batch_item_id.is_some());
    assert_eq!(
        batch_item.unique_batch_item_id,
        request_message.unique_batch_item_id
    );
    assert_eq!(
        response_payload,
        &Operation::GetAttributesResponse(GetAttributesResponse {
            unique_identifier: "1".to_owned(),
            attribute: None,
        })
    );

}


const ADD_ATTRIBUTE: &str = "42007801000001b04200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042000d0200000004000000030000000042000f010000008042005c05000000040000000d000000004200930800000008514c4b4301000000420079010000005842009407000000013200000000000000420008010000004042000a0700000011782d50726f647563745f56657273696f6e0000000000000042000b0700000014372e302e33206275696c642d31393438303836360000000042000f010000006842005c05000000040000000d000000004200930800000008514c4b4302000000420079010000004042009407000000013200000000000000420008010000002842000a0700000008782d56656e646f7242000b070000000c564d776172652c20496e632e0000000042000f010000007042005c05000000040000000d000000004200930800000008514c4b4303000000420079010000004842009407000000013200000000000000420008010000003042000a0700000009782d50726f647563740000000000000042000b070000000e564d7761726520765370686572650000";
// The PyKMIP server does not support this operation, so the response is empty

#[test]
fn add_attribute() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    let request = hex::decode(ADD_ATTRIBUTE).unwrap();

    let (major, minor) = TTLV::find_version(&request).unwrap();
    assert_eq!(major, 1);
    assert_eq!(minor, 1);

    let ttlv = TTLV::from_bytes(&request, KmipFlavor::Kmip1).unwrap();
    info!("request ttlv: {:#?}", ttlv);

    let request_message: RequestMessage = from_ttlv(ttlv).unwrap();
    assert_eq!(request_message.batch_item.len(), 3);

    let RequestMessageBatchItemVersioned::V14(batch_item) = &request_message.batch_item[0]
    else {
        panic!("Expected V14 request message");
    };
    info!("Batch Item 1: {:#?}", batch_item);
    assert_eq!(
        batch_item.request_payload,
        Operation::AddAttribute(AddAttribute {
            unique_identifier: "2".to_owned(),
            attribute: Attribute::CustomAttribute((
                "x-Product_Version".to_owned(),
                CustomAttributeValue::TextString("7.0.3 build-19480866".to_owned())
            )),
        })
    );
    
    let RequestMessageBatchItemVersioned::V14(batch_item) = &request_message.batch_item[1]
    else {
        panic!("Expected V14 request message");
    };
    info!("Batch Item 2: {:#?}", batch_item);
    assert_eq!(
        batch_item.request_payload,
        Operation::AddAttribute(AddAttribute {
            unique_identifier: "2".to_owned(),
            attribute: Attribute::CustomAttribute((
                "x-Vendor".to_owned(),
                CustomAttributeValue::TextString("VMware, Inc.".to_owned())
            )),
        })
    );
    
    let RequestMessageBatchItemVersioned::V14(batch_item) = &request_message.batch_item[2]
    else {
        panic!("Expected V14 request message");
    };
    info!("Batch Item 3: {:#?}", batch_item);
    assert_eq!(
        batch_item.request_payload,
        Operation::AddAttribute(AddAttribute {
            unique_identifier: "2".to_owned(),
            attribute: Attribute::CustomAttribute((
                "x-Product".to_owned(),
                CustomAttributeValue::TextString("VMware vSphere".to_owned())
            )),
        })
    );


}


const GET: &str = "42007801000000804200770100000038420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042000d0200000004000000010000000042000f010000003842005c05000000040000000a000000004200930800000008514c4b4301000000420079010000001042009407000000013200000000000000";
const GET_RESPONSE: &str = "42007b010000012042007a0100000048420069010000002042006a0200000004000000010000000042006b0200000004000000010000000042009209000000080000000067ee614842000d0200000004000000010000000042000f01000000c842005c05000000040000000a000000004200930800000008514c4b430100000042007f0500000004000000000000000042007c0100000090420057050000000400000002000000004200940700000001320000000000000042008f0100000068420040010000006042004205000000040000000100000000420045010000002842004308000000201c5d9de2a8baf74903d662382546c085edb2feed0c279465394b418cc7a613bd4200280500000004000000030000000042002a02000000040000010000000000";

