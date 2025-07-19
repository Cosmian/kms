use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::{TTLV, from_ttlv, to_ttlv};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::kmip_operations::Operation,
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use tracing::info;

use crate::tests::ttlv_tests::{get_client, socket_client::SocketClient};

const DISCOVER_VERSIONS_1: &str = "42007801000000604200770100000038420069010000002042006a02000000040000000100000000\
42006b0200000004000000010000000042000d02000000040000000100000000\
42000f010000001842005c05000000040000001e000000004200790100000000";

const QUERY: &str = "42007801000000804200770100000038420069010000002042006a0200000004000000010000000042006b\
0200000004000000010000000042000d0200000004000000010000000042000f010000003842005c050000\
000400000018000000004200930800000008514c4b4301000000420079010000001042007405000000040000000300000000";

const CREATE: &str =
    "420078010000013042007701000000384200690100000020\
    42006a0200000004000000010000000042006b0200000004000000010000000042000d02000000040000000100000000\
    42000f01000000e842005c050000000400000001000000004200930800000008514c4b430100000042007901000000c0\
    4200570500000004000000020000000042009101000000a8420008010000003042000a070000001743727970746f6772\
    617068696320416c676f726974686d0042000b05000000040000000300000000420008010000003042000a07000000\
    1843727970746f67726170686963205573616765204d61736b42000b02000000040000000c00000000420008010000\
    003042000a070000001443727970746f67726170686963204c656e6774680000000042000b0200000004000001000\
    0000000";

const GET_ATTRIBUTES: &str = "420078010000\
00a04200770100000038420069010000002042006a0200000004000000010000000042006b020000000400000001\
0000000042000d0200000004000000010000000042000f010000005842005c0500000004000000\
0b000000004200930800000008514c4b4301000000420079010000003042009407000000013100\
00000000000042000a0700000011782d50726f647563745f56657273696f6e00000000000000";

const ADD_ATTRIBUTE: &str = "42007801000001b042007701000000384200690100000020\
42006a0200000004000000010000000042006b0200000004000000010000000042000d02000000040000000300000000\
42000f010000008042005c05000000040000000d000000004200930800000008514c4b43010000004200790100000058\
42009407000000013100000000000000420008010000004042000a0700000011782d50726f647563745f56657273696f6e00000000000000\
42000b0700000014372e302e33206275696c642d31393438303836360000000042000f010000006842005c05000000040000000d00000000\
4200930800000008514c4b43020000004200790100000040420094070000000131000000000000004200080100000028\
42000a0700000008782d56656e646f7242000b070000000c564d776172652c20496e632e00000000\
42000f010000007042005c05000000040000000d000000004200930800000008514c4b4303000000\
4200790100000048420094070000000131000000000000004200080100000030\
42000a0700000009782d50726f647563740000000000000042000b070000000e564d7761726520765370686572650000";

const GET: &str = "42007801000000804200770100000038420069010000002042006a0200000004000000010000000042006b\
0200000004000000010000000042000d0200000004000000010000000042000f010000003842005c0500000004\
0000000a000000004200930800000008514c4b4301000000420079010000001042009407000000013200000000000000";

#[test]
fn test_vmware() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("info,kmip=debug"));

    let client = get_client();

    discover_versions_1(&client);

    query(&client);

    let uid = create_symmetric_key(&client);

    get_attributes(&client, &uid);

    add_attributes(&client, &uid);

    get_attributes(&client, &uid);

    get_symmetric_key(&client, &uid);
}

fn discover_versions_1(client: &SocketClient) {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(DISCOVER_VERSIONS_1).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let request_message: RequestMessage =
        from_ttlv(ttlv_request).expect("Failed to parse DiscoverVersions");

    info!("Discovering KMIP versions with request: {request_message:#?}",);

    // Use the raw request to send the DiscoverVersions operation
    let response = client
        .send_raw_request(&hex::decode(DISCOVER_VERSIONS_1).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse DiscoverVersions response");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.response_header.batch_count, 1);
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::DiscoverVersionsResponse(discover_response)) = &batch_item.response_payload
    else {
        panic!("Expected DiscoverVersions");
    };

    let Some(protocols) = discover_response.protocol_version.as_ref() else {
        panic!("Expected protocol versions");
    };
    assert_eq!(protocols.len(), 7); // 2.1, 2.0, 1.4, 1.3, 1.2, 1.1, 1.0

    info!("DiscoverVersions response: {discover_response:#?}");
}

fn query(client: &SocketClient) {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(QUERY).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let request_message: RequestMessage = from_ttlv(ttlv_request).expect("Failed to parse Query");

    info!("Querying with request: {request_message:#?}",);

    // Use the raw request to send the Query operation
    let response = client
        .send_raw_request(&hex::decode(QUERY).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse Query response");

    info!("Query response: {response:#?}");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
}

fn create_symmetric_key(client: &SocketClient) -> String {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(CREATE).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let request_message: RequestMessage = from_ttlv(ttlv_request).expect("Failed to parse Create");

    info!("Creating symmetric key with request: {request_message:#?}",);

    // Use the raw request to send the Create operation
    let response = client
        .send_raw_request(&hex::decode(CREATE).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse Create response");

    info!("Create response: {response:#?}");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::CreateResponse(create_response)) = &batch_item.response_payload else {
        panic!("Expected Create");
    };

    assert!(!create_response.unique_identifier.is_empty());
    create_response.unique_identifier.clone()
}

fn get_attributes(client: &SocketClient, uid: &str) {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(GET_ATTRIBUTES).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let mut request_message: RequestMessage =
        from_ttlv(ttlv_request).expect("Failed to parse GetAttributes");
    let Some(RequestMessageBatchItemVersioned::V14(batch_item)) =
        request_message.batch_item.get_mut(0)
    else {
        panic!("Expected V14 batch item");
    };
    let Operation::GetAttributes(get_attributes_request) = &mut batch_item.request_payload else {
        panic!("Expected GetAttributes operation");
    };
    get_attributes_request.unique_identifier = uid.to_owned();
    info!("Getting attributes with request: {request_message:#?}",);
    let raw_request = to_ttlv(&request_message)
        .expect("Failed to encode request")
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to convert TTLV to bytes");

    let response = client
        .send_raw_request(&raw_request)
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse GetAttributes response");

    info!("GetAttributes response: {response:#?}");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(_get_attributes_response)) =
        &batch_item.response_payload
    else {
        panic!("Expected GetAttributes");
    };
}

fn add_attributes(client: &SocketClient, uid: &str) {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(ADD_ATTRIBUTE).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    info!("Adding attributes with request: {ttlv_request:#?}");
    let mut request_message: RequestMessage =
        from_ttlv(ttlv_request).expect("Failed to parse AddAttribute");
    for batch_item in &mut request_message.batch_item {
        if let RequestMessageBatchItemVersioned::V14(batch_item) = batch_item {
            if let Operation::AddAttribute(add_attribute_request) = &mut batch_item.request_payload
            {
                add_attribute_request.unique_identifier = uid.to_owned();
            } else {
                panic!("Expected AddAttribute operation");
            }
        } else {
            panic!("Expected V14 batch item");
        }
    }
    info!("Adding attributes with request: {request_message:#?}",);
    let raw_request = to_ttlv(&request_message)
        .expect("Failed to encode request")
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to convert TTLV to bytes");

    let response = client
        .send_raw_request(&raw_request)
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse AddAttribute response");

    info!("AddAttribute response: {response:#?}");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 3);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::AddAttributeResponse(_add_attribute_response)) =
        &batch_item.response_payload
    else {
        panic!("Expected AddAttribute");
    };
}

fn get_symmetric_key(client: &SocketClient, uid: &str) {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(GET).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let mut request_message: RequestMessage = from_ttlv(ttlv_request).expect("Failed to parse Get");
    let Some(RequestMessageBatchItemVersioned::V14(batch_item)) =
        request_message.batch_item.get_mut(0)
    else {
        panic!("Expected V14 batch item");
    };
    let Operation::Get(get_request) = &mut batch_item.request_payload else {
        panic!("Expected Get operation");
    };
    get_request.unique_identifier = uid.to_owned();
    info!("Getting symmetric key with request: {request_message:#?}",);
    let raw_request = to_ttlv(&request_message)
        .expect("Failed to encode request")
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to convert TTLV to bytes");

    let response = client
        .send_raw_request(&raw_request)
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");

    info!("Get response: {ttlv_response:#?}");

    let response: ResponseMessage = from_ttlv(ttlv_response).expect("Failed to parse Get response");

    info!("Get response: {response:#?}");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetResponse(_get_response)) = &batch_item.response_payload else {
        panic!("Expected Get");
    };
}
