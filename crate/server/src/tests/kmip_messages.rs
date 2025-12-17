#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            BlockCipherMode, ErrorReason, HashingAlgorithm, ProtocolVersion,
            ResultStatusEnumeration,
        },
    },
    kmip_2_1::{
        extra::tagging::EMPTY_TAGS,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Decrypt, Encrypt, MAC, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, OperationEnumeration,
            RecommendedCurve, UniqueIdentifier,
        },
        requests::{create_ec_key_pair_request, symmetric_key_create_request},
    },
    ttlv::to_ttlv,
};
use cosmian_logger::{debug, log_init};

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_kmip_mac_messages() -> KResult<()> {
    // Disable most logging
    log_init(Some("warn"));

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let symmetric_key_request = symmetric_key_create_request(
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;

    let unique_identifier = Some(
        kms.create(symmetric_key_request, owner, None)
            .await?
            .unique_identifier,
    );
    let mac_request = MAC {
        unique_identifier,
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA3512),
            ..Default::default()
        }),
        data: Some(vec![0; 32]),
        ..Default::default()
    };

    // prepare and send the single message
    let items_number = 10_000;
    let items: Vec<RequestMessageBatchItemVersioned> = (0..items_number)
        .map(|_| {
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::MAC(
                mac_request.clone(),
            )))
        })
        .collect();
    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            batch_count: items_number,
            ..Default::default()
        },
        batch_item: items,
    };

    let response = kms.message(message_request, owner).await?;
    assert_eq!(response.response_header.batch_count, items_number);
    // Check that all operations succeeded
    for item in &response.batch_item {
        let ResponseMessageBatchItemVersioned::V21(item) = item else {
            panic!("not a V21 response");
        };
        assert_eq!(item.result_status, ResultStatusEnumeration::Success);
        assert_eq!(item.operation, Some(OperationEnumeration::MAC));
        assert!(matches!(
            item.response_payload,
            Some(Operation::MACResponse(_))
        ));
    }
    assert_eq!(
        response.batch_item.len(),
        usize::try_from(items_number).unwrap()
    );

    log_init(option_env!("RUST_LOG"));
    Ok(())
}

#[tokio::test]
async fn test_encrypt_kmip_messages() -> KResult<()> {
    // Disable most logging
    log_init(Some("warn"));
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    // Create a symmetric key first

    let symmetric_key_request = symmetric_key_create_request(
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;

    let unique_identifier = Some(
        kms.create(symmetric_key_request, owner, None)
            .await?
            .unique_identifier,
    );

    let encrypt_request = Encrypt {
        unique_identifier: unique_identifier.clone(),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::XTS),
            ..Default::default()
        }),
        data: Some(vec![0_u8; 32].into()),
        i_v_counter_nonce: Some(vec![0_u8; 16]),
        ..Default::default()
    };

    // prepare and send multiple encrypt requests
    let items_number = 10_000;
    let items: Vec<RequestMessageBatchItemVersioned> = (0..items_number)
        .map(|_| {
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Encrypt(
                Box::new(encrypt_request.clone()),
            )))
        })
        .collect();

    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: items_number,
            ..Default::default()
        },
        batch_item: items,
    };

    let response = kms.message(message_request, owner).await?;
    assert_eq!(response.response_header.batch_count, items_number);
    assert_eq!(
        response.batch_item.len(),
        usize::try_from(items_number).unwrap()
    );

    // Check that all operations succeeded
    for item in response.batch_item {
        let ResponseMessageBatchItemVersioned::V21(item) = item else {
            panic!("not a V21 response");
        };
        assert_eq!(item.result_status, ResultStatusEnumeration::Success);
        assert_eq!(item.operation, Some(OperationEnumeration::Encrypt));
        assert!(matches!(
            item.response_payload,
            Some(Operation::EncryptResponse(_))
        ));
    }

    log_init(option_env!("RUST_LOG"));
    Ok(())
}

#[tokio::test]
async fn test_kmip_messages() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let ec_create_request =
        create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519, false, None)?;

    // prepare and send the single message
    let batch_item = vec![
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
            Operation::CreateKeyPair(Box::new(ec_create_request)),
        )),
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Locate(
            Box::default(),
        ))),
        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(Operation::Decrypt(
            Box::new(Decrypt {
                unique_identifier: Some(UniqueIdentifier::TextString("id_12345".to_owned())),
                data: Some(b"decrypted_data".to_vec()),
                ..Default::default()
            }),
        ))),
    ];
    let message_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            batch_count: 3,
            ..Default::default()
        },
        batch_item,
    };
    debug!("message_request: {:#?}", to_ttlv(&message_request));

    let response = kms.message(message_request, owner).await?;
    assert_eq!(response.response_header.batch_count, 3);
    assert_eq!(response.batch_item.len(), 3);

    // 1. Create keypair
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("not a V21 response");
    };
    assert_eq!(
        batch_item.operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::CreateKeyPairResponse(create_keypair_response)) =
        &batch_item.response_payload
    else {
        panic!("not a create key pair response payload");
    };

    // 2. Locate
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[1] else {
        panic!("not a V21 response");
    };
    assert_eq!(batch_item.operation, Some(OperationEnumeration::Locate));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "result_status: {:?}, result_message: {:?}, result_reason: {:?}",
        batch_item.result_status,
        batch_item.result_message,
        batch_item.result_reason
    );
    let Some(Operation::LocateResponse(locate_response)) = &batch_item.response_payload else {
        panic!("not a locate response payload");
    };
    // locate response contains only 2 keys, the pair that was created
    // by the first batch item, because processing is sequential and order is preserved
    assert_eq!(locate_response.located_items, Some(2));
    let locate_uids = locate_response.unique_identifier.clone().unwrap();
    assert_eq!(locate_uids.len(), 2);
    assert!(locate_uids.contains(&create_keypair_response.private_key_unique_identifier));
    assert!(locate_uids.contains(&create_keypair_response.public_key_unique_identifier));

    // 3. Decrypt (that failed)
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[2] else {
        panic!("not a V21 response");
    };

    assert_eq!(batch_item.operation, Some(OperationEnumeration::Decrypt));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        batch_item.result_message,
        Some("Decrypt: failed to retrieve the key: id_12345".to_owned())
    );
    assert_eq!(batch_item.result_reason, Some(ErrorReason::Item_Not_Found));
    assert!(batch_item.response_payload.is_none());
    Ok(())
}
