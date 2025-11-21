use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Get, Operation},
        kmip_types::{CryptographicAlgorithm, OperationEnumeration, UniqueIdentifier},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_create_get_dsa_roundtrip() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();

    // 1. Create DSA key
    let create_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Create,
                ephemeral: None,
                unique_batch_item_id: Some(b"dsa-rt-create".to_vec()),
                request_payload: Operation::Create(Create {
                    object_type: ObjectType::PrivateKey,
                    attributes: Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::DSA),
                        cryptographic_length: Some(2048),
                        ..Default::default()
                    },
                    protection_storage_masks: None,
                }),
                message_extension: None,
            },
        )],
    };
    let create_response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &create_request)
        .expect("Create DSA request failed");
    let ResponseMessageBatchItemVersioned::V21(create_batch) = &create_response.batch_item[0]
    else {
        panic!("Expected KMIP 2.1 batch item");
    };
    assert_eq!(
        create_batch.result_status,
        ResultStatusEnumeration::Success,
        "Create DSA failed: {:?} {:?}",
        create_batch.result_reason,
        create_batch.result_message
    );
    let Operation::CreateResponse(cr) = create_batch
        .response_payload
        .as_ref()
        .expect("Missing create response payload")
    else {
        panic!("Expected CreateResponse");
    };
    let uid = cr.unique_identifier.to_string();
    assert!(!uid.is_empty(), "UID must not be empty");

    // 2. Get same key
    let get_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Get,
                ephemeral: None,
                unique_batch_item_id: Some(b"dsa-rt-get".to_vec()),
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrap_type: None,
                    key_wrapping_specification: None,
                }),
                message_extension: None,
            },
        )],
    };
    let get_response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &get_request)
        .expect("Get DSA request failed");
    let ResponseMessageBatchItemVersioned::V21(get_batch) = &get_response.batch_item[0] else {
        panic!("Expected KMIP 2.1 batch item");
    };
    assert_eq!(
        get_batch.result_status,
        ResultStatusEnumeration::Success,
        "Get DSA failed: {:?} {:?}",
        get_batch.result_reason,
        get_batch.result_message
    );
    let Operation::GetResponse(gr) = get_batch
        .response_payload
        .as_ref()
        .expect("Missing GetResponse")
    else {
        panic!("Expected GetResponse");
    };
    assert_eq!(gr.object_type, ObjectType::PrivateKey);
    let key_block = gr.object.key_block().expect("KeyBlock missing");
    assert_eq!(key_block.key_format_type, cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType::TransparentDSAPrivateKey);
    if let Some(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_data_structures::KeyValue::Structure { key_material, .. }) = &key_block.key_value {
        match key_material { cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDSAPrivateKey { p, .. } => { let bits = p.bits(); assert_eq!(bits, 2048, "Expected 2048-bit DSA p, got {bits}"); }, _ => panic!("Unexpected key material variant") }
    } else { panic!("Missing KeyValue structure") }
}
