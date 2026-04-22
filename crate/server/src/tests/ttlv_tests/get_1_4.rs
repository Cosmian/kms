use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::Object,
        kmip_operations::{Get, Operation},
        kmip_types::{KeyFormatType, ObjectType, OperationEnumeration},
    },
    ttlv::{KmipFlavor, TTLV, from_ttlv, to_ttlv},
};
use cosmian_logger::{info, log_init};

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_get_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id}");

    // Get the symmetric key
    get_symmetric_key(&client, &key_id);
}

pub(super) fn get_symmetric_key(client: &SocketClient, key_id: &str) {
    let protocol_major = 1;
    let protocol_minor = 4;
    let kmip_flavor = if protocol_major == 2 {
        KmipFlavor::Kmip2
    } else {
        KmipFlavor::Kmip1
    };

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: protocol_major,
                protocol_version_minor: protocol_minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Get,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(key_id.to_owned()),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrapping_specification: None,
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(kmip_flavor, &request_message)
        .expect("Failed to send request");

    // KMIP 1.4 behavior check: `Fresh` is supported for KMIP > 1.0.
    let response_ttlv: TTLV = to_ttlv(&response).expect("Failed to convert response to TTLV");
    let response_bytes = response_ttlv
        .to_bytes(kmip_flavor)
        .expect("Failed to serialize response TTLV");
    assert!(
        response_bytes
            .windows(b"Fresh".len())
            .any(|w| w == b"Fresh"),
        "KMIP 1.4 Get response should include Fresh when present (TTLV missing \"Fresh\")"
    );

    // Safety: ensure the TTLV roundtrip decoding still works.
    let decoded_ttlv = TTLV::from_bytes(&response_bytes, kmip_flavor)
        .expect("Failed to decode serialized response TTLV");
    let _decoded: ResponseMessage = from_ttlv(decoded_ttlv).expect("Failed to decode response");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: protocol_major,
            protocol_version_minor: protocol_minor,
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
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::GetResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(response.unique_identifier, key_id.to_owned());
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
