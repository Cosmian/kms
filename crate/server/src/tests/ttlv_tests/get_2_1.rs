use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{KeyWrapType, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Get, Operation},
        kmip_types::{KeyFormatType, OperationEnumeration, UniqueIdentifier},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use log::info;

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_get_2_1() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id}");

    // Get the symmetric key
    get_symmetric_key(&client, &key_id);
}

pub(crate) fn get_symmetric_key(client: &SocketClient, key_id: &str) {
    let protocol_major = 2;
    let kmip_flavor = if protocol_major == 2 {
        KmipFlavor::Kmip2
    } else {
        KmipFlavor::Kmip1
    };

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: protocol_major,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Get,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrapping_specification: None,
                    key_wrap_type: Some(KeyWrapType::NotWrapped),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(kmip_flavor, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: protocol_major,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::GetResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(key_id.to_owned())
    );
    assert_eq!(response.object_type, ObjectType::SymmetricKey);
    let Object::SymmetricKey(symmetric_key) = response.object.clone() else {
        panic!("Expected SymmetricKey");
    };
    assert_eq!(symmetric_key.key_block.key_format_type, KeyFormatType::Raw);
    assert_eq!(symmetric_key.key_block.key_compression_type, None);
    let Some(KeyValue::Structure { key_material, .. }) = symmetric_key.key_block.key_value else {
        panic!("Expected key_value");
    };
    let KeyMaterial::ByteString(bytes) = key_material else {
        panic!("Expected ByteString");
    };
    assert_eq!(bytes.len(), 32);
}
