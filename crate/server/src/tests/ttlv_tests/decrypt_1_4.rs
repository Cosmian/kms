use cosmian_kms_server_database::reexport::cosmian_kmip::{
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
        kmip_operations::{Decrypt, Operation},
        kmip_types::{CryptographicAlgorithm, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use log::info;

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::{encrypt_1_4::encrypt, get_client};

#[test]
fn test_decrypt_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id}");

    // Get the symmetric key
    let (nonce, data, tag) = encrypt(&client, &key_id, b"Hello, world!", None);

    let data = decrypt(&client, &key_id, &nonce, &data, &tag, None);
    assert_eq!(data, b"Hello, world!");
}

pub(crate) fn decrypt(
    client: &SocketClient,
    key_id: &str,
    nonce: &[u8],
    data: &[u8],
    tag: &[u8],
    aad: Option<&[u8]>,
) -> Vec<u8> {
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
                operation: OperationEnumeration::Decrypt,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Decrypt(Box::new(Decrypt {
                    unique_identifier: key_id.to_owned(),
                    cryptographic_parameters: Some(CryptographicParameters {
                        block_cipher_mode: Some(BlockCipherMode::GCM),
                        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                        ..Default::default()
                    }),
                    data: Some(data.to_vec()),
                    i_v_counter_nonce: Some(nonce.to_vec()),
                    correlation_value: None,
                    init_indicator: None,
                    final_indicator: None,
                    authenticated_encryption_additional_data: aad.map(Vec::from),
                    authenticated_encryption_tag: Some(tag.to_vec()),
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
    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::DecryptResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(response.unique_identifier, key_id.to_owned());
    assert!(response.data.is_some());
    let data = response.data.as_ref().unwrap();
    data.clone()
}
