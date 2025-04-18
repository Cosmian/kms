use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{BlockCipherMode, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_data_structures::CryptographicParameters,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Encrypt, Operation},
        kmip_types::{CryptographicAlgorithm, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_kms_client::SocketClient;
use cosmian_logger::log_init;
use log::info;

use super::create_1_4::create_symmetric_key;
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_encrypt_1_4() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client);
    info!("Key ID: {}", key_id);

    // Get the symmetric key
    encrypt(&client, &key_id, b"Hello, world!", None);
}

pub(crate) fn encrypt(
    client: &SocketClient,
    key_id: &str,
    data: &[u8],
    aad: Option<&[u8]>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let protocol_major = 1;
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
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Encrypt,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Encrypt(Encrypt {
                    unique_identifier: key_id.to_owned(),
                    cryptographic_parameters: Some(CryptographicParameters {
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        ..Default::default()
                    }),
                    data: Some(data.to_vec()),
                    i_v_counter_nonce: None,
                    correlation_value: None,
                    init_indicator: None,
                    final_indicator: None,
                    authenticated_encryption_additional_data: aad.map(Vec::from),
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
            protocol_version_minor: 3,
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
    let Some(Operation::EncryptResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(response.unique_identifier, key_id.to_owned());
    assert!(response.data.is_some());
    assert!(response.i_v_counter_nonce.is_some());
    assert!(response.authenticated_encryption_tag.is_some());

    (
        response.i_v_counter_nonce.clone().unwrap(),
        response.data.clone().unwrap(),
        response.authenticated_encryption_tag.clone().unwrap(),
    )
}
