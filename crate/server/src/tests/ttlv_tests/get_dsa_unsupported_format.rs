use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ErrorReason, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Get, Operation},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, OperationEnumeration, UniqueIdentifier,
        },
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_get_dsa_unsupported_format() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();

    // Create a DSA key first
    let create_req = RequestMessage {
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
                unique_batch_item_id: Some(b"dsa-get-uf-create".to_vec()),
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
    let create_resp = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &create_req)
        .expect("Create DSA failed");
    let ResponseMessageBatchItemVersioned::V21(create_batch) = &create_resp.batch_item[0] else {
        panic!("Expected 2.1 batch item");
    };
    assert_eq!(
        create_batch.result_status,
        ResultStatusEnumeration::Success,
        "Create should succeed"
    );
    let Operation::CreateResponse(cr) = create_batch
        .response_payload
        .as_ref()
        .expect("Missing create response")
    else {
        panic!("Expected CreateResponse");
    };
    let uid = cr.unique_identifier.to_string();

    // Attempt Get requesting PKCS8 (unsupported conversion for DSA Transparent -> PKCS8 currently)
    let get_req = RequestMessage {
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
                unique_batch_item_id: Some(b"dsa-get-uf".to_vec()),
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(UniqueIdentifier::TextString(uid)),
                    key_format_type: Some(KeyFormatType::PKCS8),
                    key_compression_type: None,
                    key_wrap_type: None,
                    key_wrapping_specification: None,
                }),
                message_extension: None,
            },
        )],
    };
    let get_resp = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &get_req)
        .expect("Get DSA unsupported format failed");
    let ResponseMessageBatchItemVersioned::V21(get_batch) = &get_resp.batch_item[0] else {
        panic!("Expected 2.1 batch item");
    };
    assert_eq!(
        get_batch.result_status,
        ResultStatusEnumeration::OperationFailed,
        "Expected OperationFailed for unsupported DSA format"
    );
    assert_eq!(
        get_batch.result_reason,
        Some(ErrorReason::Operation_Not_Supported),
        "Expected NotSupported reason"
    );
}
