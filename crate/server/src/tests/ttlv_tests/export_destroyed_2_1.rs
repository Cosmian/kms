//! KMIP 2.1 §6.1.18: Export of a Destroyed object succeeds, but its key material is not returned.
//! Get of a Destroyed object keeps failing with `Object_Destroyed`.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            CryptographicUsageMask, ErrorReason, ProtocolVersion, ResultStatusEnumeration,
        },
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_messages::{RequestMessageBatchItem, ResponseMessageBatchItem},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Create, Destroy, Export, Get, Operation},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

fn send(operation: Operation) -> ResponseMessage {
    get_client()
        .send_request::<RequestMessage, ResponseMessage>(
            KmipFlavor::Kmip2,
            &RequestMessage {
                request_header: RequestMessageHeader {
                    protocol_version: ProtocolVersion {
                        protocol_version_major: 2,
                        protocol_version_minor: 1,
                    },
                    batch_count: 1,
                    ..Default::default()
                },
                batch_item: vec![RequestMessageBatchItemVersioned::V21(
                    RequestMessageBatchItem::new(operation),
                )],
            },
        )
        .expect("Failed to send request")
}

fn first_item(response: &ResponseMessage) -> &ResponseMessageBatchItem {
    let Some(ResponseMessageBatchItemVersioned::V21(item)) = response.batch_item.first() else {
        panic!("Expected a KMIP 2.1 response batch item");
    };
    item
}

#[test]
fn test_export_destroyed_key_returns_no_key_material() {
    log_init(option_env!("RUST_LOG"));

    // A freshly created key is Pre-Active, which can be destroyed directly.
    let create = send(Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    }));
    let Some(Operation::CreateResponse(created)) = &first_item(&create).response_payload else {
        panic!("Expected a CreateResponse");
    };
    let uid = created.unique_identifier.clone();

    let destroy = send(Operation::Destroy(Destroy {
        unique_identifier: Some(uid.clone()),
        ..Default::default()
    }));
    assert_eq!(
        first_item(&destroy).result_status,
        ResultStatusEnumeration::Success
    );

    // Export succeeds, without key material
    let export = send(Operation::Export(Export {
        unique_identifier: Some(uid.clone()),
        ..Default::default()
    }));
    let item = first_item(&export);
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::ExportResponse(exported)) = &item.response_payload else {
        panic!("Expected an ExportResponse");
    };
    let Object::SymmetricKey(key) = &exported.object else {
        panic!("Expected a SymmetricKey");
    };
    let Some(KeyValue::Structure { key_material, .. }) = &key.key_block.key_value else {
        panic!("Expected a key value structure");
    };
    let KeyMaterial::ByteString(bytes) = key_material else {
        panic!("Expected a byte string key material");
    };
    assert!(bytes.is_empty(), "key material must not be returned");

    // Get keeps failing with Object_Destroyed
    let get = send(Operation::Get(Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        ..Default::default()
    }));
    let item = first_item(&get);
    assert_eq!(item.result_status, ResultStatusEnumeration::OperationFailed);
    assert_eq!(item.result_reason, Some(ErrorReason::Object_Destroyed));
}
