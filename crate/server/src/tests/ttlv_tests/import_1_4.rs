use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::{KeyBlock, KeyValue},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::{Object, SymmetricKey},
        kmip_operations::{Import, Operation},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, OperationEnumeration, UniqueIdentifier,
        },
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use zeroize::Zeroizing;

use super::socket_client::SocketClient;
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_import_1_4() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();

    // import a symmetric key
    import_symmetric_key(&client);
}

pub(super) fn import_symmetric_key(client: &SocketClient) -> String {
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_value: Some(KeyValue::ByteString(Zeroizing::new(vec![1, 2, 3, 4]))),
            key_compression_type: None,
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 1,

            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Import,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Import(Import {
                    unique_identifier: UniqueIdentifier::from("imported_1_4_key_uid".to_owned()),
                    replace_existing: Some(false),
                    key_wrap_type: None,
                    attribute: Some(vec![
                        Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                        Attribute::CryptographicUsageMask(
                            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                        ),
                        Attribute::CryptographicLength(256),
                    ]),
                    object,
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send request");

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
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));

    let Some(Operation::ImportResponse(import_response)) = &batch_item.response_payload else {
        panic!("Expected Import");
    };

    assert_eq!(import_response.unique_identifier, "imported_1_4_key_uid");
    import_response.unique_identifier.clone()
}
