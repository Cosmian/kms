use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_messages::{Message, MessageBatchItem, MessageHeader},
    kmip_operations::{Decrypt, ErrorReason, Locate, Mac, Operation},
    kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, OperationEnumeration, ProtocolVersion,
        RecommendedCurve, ResultStatusEnumeration, UniqueIdentifier,
    },
    requests::{create_ec_key_pair_request, symmetric_key_create_request},
};

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

#[tokio::test]
#[allow(clippy::as_conversions)]
async fn test_kmip_mac_messages() -> KResult<()> {
    // cosmian_logger::log_init("info,hyper=info,reqwest=info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
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
    let mac_request = Mac {
        unique_identifier,
        cryptographic_parameters: CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::SHA3256),
            ..Default::default()
        },
        data: Some([1, 2, 3, 4].to_vec()),
        ..Default::default()
    };

    // prepare and send the single message
    let items_number = 1000;
    let items: Vec<MessageBatchItem> = (0..items_number)
        .map(|_| MessageBatchItem::new(Operation::Mac(mac_request.clone())))
        .collect();
    let message_request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            batch_count: 1,
            ..Default::default()
        },
        items,
    };

    let response = kms.message(message_request, owner, None).await?;
    assert_eq!(response.header.batch_count, items_number);
    assert_eq!(response.items.len(), items_number as usize);

    Ok(())
}

#[tokio::test]
async fn test_kmip_messages() -> KResult<()> {
    // cosmian_logger::log_init("info,hyper=info,reqwest=info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMS::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let ec_create_request =
        create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519, false)?;

    // prepare and send the single message
    let items = vec![
        MessageBatchItem::new(Operation::CreateKeyPair(ec_create_request)),
        MessageBatchItem::new(Operation::Locate(Locate::default())),
        MessageBatchItem::new(Operation::Decrypt(Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString("id_12345".to_owned())),
            data: Some(b"decrypted_data".to_vec()),
            ..Default::default()
        })),
    ];
    let message_request = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            // wrong number of items but it is only checked
            // when TTLV-serialization is done
            batch_count: 1,
            ..Default::default()
        },
        items,
    };

    let response = kms.message(message_request, owner, None).await?;
    assert_eq!(response.header.batch_count, 3);
    assert_eq!(response.items.len(), 3);

    // 1. Create keypair
    assert_eq!(
        response.items[0].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.items[0].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(create_keypair_response)) =
        &response.items[0].response_payload
    else {
        panic!("not a create key pair response payload");
    };

    // 2. Locate
    assert_eq!(
        response.items[1].operation,
        Some(OperationEnumeration::Locate)
    );
    assert_eq!(
        response.items[1].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::LocateResponse(locate_response)) = &response.items[1].response_payload
    else {
        panic!("not a locate response payload");
    };
    // locate response contains only 2 keys, the pair that was created
    // by the first batch item, because processing is sequential and order is preserved
    assert_eq!(locate_response.located_items, Some(2));
    let locate_uids = locate_response.unique_identifiers.clone().unwrap();
    assert_eq!(locate_uids.len(), 2);
    assert!(locate_uids.contains(&create_keypair_response.private_key_unique_identifier));
    assert!(locate_uids.contains(&create_keypair_response.public_key_unique_identifier));

    // 3. Decrypt (that failed)
    assert_eq!(
        response.items[2].operation,
        Some(OperationEnumeration::Decrypt)
    );
    assert_eq!(
        response.items[2].result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        response.items[2].result_message,
        Some("Decrypt: failed to retrieve the key: id_12345".to_owned())
    );
    assert_eq!(
        response.items[2].result_reason,
        Some(ErrorReason::Item_Not_Found)
    );
    assert!(response.items[2].response_payload.is_none());
    Ok(())
}
