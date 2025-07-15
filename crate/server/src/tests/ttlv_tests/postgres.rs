use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::{TTLV, from_ttlv};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{kmip_objects::Object, kmip_operations::Operation},
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use tracing::info;

use super::socket_client::SocketClient;
use crate::tests::ttlv_tests::get_client;

const REGISTER_KEY: &str = "42007801000001f842007701000000584200690100000020\
42006a0200000004000000010000000042006b0200000004000000040000000042005002000000040000200000000000\
4200920900000008000000006871175042000d02000000040000000100000000\
42000f010000019042005c05000000040000000300000000420079010000017842005705000000040000000200000000\
42009101000000f0420008010000003042000a070000001743727970746f6772617068696320416c676f726974686d00\
42000b05000000040000000300000000420008010000003042000a070000001443727970746f67726170686963204c656e67746800000000\
42000b02000000040000008000000000420008010000003042000a070000001843727970746f67726170686963205573616765204d61736b\
42000b02000000040000000c00000000420008010000004042000a07000000044e616d6500000000\
42000b0100000028420055070000000e636c655f636f736d69616e5f303100004200540500000004000000010000000042008f0100000068\
420040010000006042004205000000040000000100000000420041050000000400000001000000004200450100000018\
4200430800000010c1be2b9c939788a7cd09a50d5870d6c04200280500000004000000030000000042002a02000000040000008000000000";

const LOCATE_KEY: &str = "42007801000001084200770100000058420069010000002042006a02000000040000000100000000\
42006b02000000040000000000000000420050020000000400002000000000004200920900000008000000006871179d\
42000d0200000004000000010000000042000f01000000a042005c050000000400000008000000004200790100000088\
42004f02000000040000001000000000420008010000002842000a070000000b4f626a65637420547970650000000000\
42000b05000000040000000200000000420008010000004042000a07000000044e616d650000000042000b0100000028\
420055070000000e636c655f636f736d69616e5f3031000042005405000000040000000100000000";

const GET_SYMMETRIC_KEY: &str = "42007801000000b04200770100000058420069010000002042006a02000000040000000100000000\
42006b02000000040000000000000000420050020000000400002000000000004200920900000008000000006871179d\
42000d0200000004000000010000000042000f010000004842005c05000000040000000a000000004200790100000030\
420094070000002439646266326261362d333664362d343965642d396261652d39303561363666643030396600000000";

#[test]
fn test_postgres() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("info"));

    let client = get_client();

    //Register a symmetric key
    let uid = register_symmetric_key(&client);

    // Locate the symmetric key
    let uids = locate_symmetric_key(&client);

    assert!(uids.contains(&uid));

    // Get the symmetric key
    let object = get_symmetric_key(&client, &uid);
    info!("Symmetric key: {object:#?}");
}

fn register_symmetric_key(client: &SocketClient) -> String {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(REGISTER_KEY).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let request_message: RequestMessage =
        from_ttlv(ttlv_request).expect("Failed to parse Register");
    info!("Registering symmetric key with request: {request_message:#?}",);

    // Use the raw request to send the Register operation
    let response = client
        .send_raw_request(&hex::decode(REGISTER_KEY).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse Register response");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 4,
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

    let Some(Operation::RegisterResponse(register_response)) = &batch_item.response_payload else {
        panic!("Expected Register");
    };

    info!("Register response: {register_response:#?}");

    assert!(!register_response.unique_identifier.is_empty());
    assert!(register_response.template_attribute.is_none());
    register_response.unique_identifier.clone()
}

fn locate_symmetric_key(client: &SocketClient) -> Vec<String> {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(LOCATE_KEY).expect("Failed to decode hex"),
        KmipFlavor::Kmip1,
    )
    .expect("Failed to parse TTLV");
    let request_message: RequestMessage = from_ttlv(ttlv_request).expect("Failed to parse Locate");

    info!("Locating symmetric key with request: {request_message:#?}",);

    // Use the raw request to send the Locate operation
    let response = client
        .send_raw_request(&hex::decode(LOCATE_KEY).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage =
        from_ttlv(ttlv_response).expect("Failed to parse Locate response");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 0,
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

    let Some(Operation::LocateResponse(locate_response)) = &batch_item.response_payload else {
        panic!("Expected Locate");
    };

    info!("Locate response: {locate_response:#?}");

    locate_response
        .unique_identifier
        .clone()
        .expect("Expected unique identifier")
}

fn get_symmetric_key(client: &SocketClient, uid: &str) -> Object {
    let ttlv_request = TTLV::from_bytes(
        &hex::decode(GET_SYMMETRIC_KEY).expect("Failed to decode hex"),
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

    // Use the raw request to send the Get operation
    let raw_request = GET_SYMMETRIC_KEY.replace(
        "39646266326261362d333664362d343965642d396261652d393035613636666430303966", // the sample key-id
        &hex::encode(uid.as_bytes()), // the newly created key-id
    );
    let response = client
        .send_raw_request(&hex::decode(raw_request).expect("Failed to decode hex"))
        .expect("Failed to send request");
    let ttlv_response =
        TTLV::from_bytes(&response, KmipFlavor::Kmip1).expect("Failed to parse TTLV response");
    let response: ResponseMessage = from_ttlv(ttlv_response).expect("Failed to parse Get response");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 0,
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

    let Some(Operation::GetResponse(get_response)) = &batch_item.response_payload else {
        panic!("Expected Get");
    };

    info!("Get response: {get_response:#?}");

    get_response.object.clone()
}
