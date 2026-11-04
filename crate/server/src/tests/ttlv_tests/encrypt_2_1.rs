use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{BlockCipherMode, ErrorReason, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Encrypt, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, OperationEnumeration, UniqueIdentifier,
        },
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};
use zeroize::Zeroizing;

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_encrypt_2_1() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id}");

    // Get the symmetric key
    encrypt(&client, &key_id, b"Hello, world!", None);
}

/// KMIP 2.1 IV Length is in bits: 12 is 12 bits, which AES-GCM rejects; 96 yields the
/// 12-byte IV.
#[test]
fn test_encrypt_2_1_iv_length_is_in_bits() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();
    let key_id = create_symmetric_key(&client, "key_iv_length");

    let send = |iv_length: i32| {
        let request_message = RequestMessage {
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
                    operation: OperationEnumeration::Encrypt,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Encrypt(Box::new(Encrypt {
                        unique_identifier: Some(UniqueIdentifier::TextString(key_id.clone())),
                        cryptographic_parameters: Some(CryptographicParameters {
                            block_cipher_mode: Some(BlockCipherMode::GCM),
                            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                            iv_length: Some(iv_length),
                            ..Default::default()
                        }),
                        data: Some(Zeroizing::new(b"Hello, world!".to_vec())),
                        ..Default::default()
                    })),
                    message_extension: None,
                },
            )],
        };
        client
            .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
            .expect("Failed to send request")
    };

    let response = send(12);
    let Some(ResponseMessageBatchItemVersioned::V21(item)) = response.batch_item.first() else {
        panic!("Expected V21 response message");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::OperationFailed);
    assert_eq!(
        item.result_reason,
        Some(ErrorReason::Bad_Cryptographic_Parameters)
    );

    let response = send(96);
    let Some(ResponseMessageBatchItemVersioned::V21(item)) = response.batch_item.first() else {
        panic!("Expected V21 response message");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::EncryptResponse(encrypted)) = &item.response_payload else {
        panic!("Expected EncryptResponse");
    };
    assert_eq!(encrypted.i_v_counter_nonce.as_ref().map(Vec::len), Some(12));
}

pub(super) fn encrypt(client: &SocketClient, key_id: &str, data: &[u8], aad: Option<&[u8]>) {
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
                protocol_version_minor: 3,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Encrypt,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Encrypt(Box::new(Encrypt {
                    unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
                    cryptographic_parameters: Some(CryptographicParameters {
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        ..Default::default()
                    }),
                    data: Some(Zeroizing::new(data.to_vec())),
                    i_v_counter_nonce: None,
                    correlation_value: None,
                    init_indicator: None,
                    final_indicator: None,
                    authenticated_encryption_additional_data: aad.map(Vec::from),
                })),
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
            protocol_version_minor: 3,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V21 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::EncryptResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(response.unique_identifier.to_string(), key_id.to_owned());
    assert!(response.data.is_some());
    assert!(response.i_v_counter_nonce.is_some());
    assert!(response.authenticated_encryption_tag.is_some());
}
