use std::sync::Arc;

use cosmian_kmip::{
    crypto::elliptic_curves::kmip_requests::create_ec_key_pair_request,
    kmip::{
        extra::tagging::EMPTY_TAGS,
        kmip_messages::{Message, MessageBatchItem, MessageHeader},
        kmip_operations::{Decrypt, ErrorReason, Locate, Operation},
        kmip_types::{
            OperationEnumeration, ProtocolVersion, RecommendedCurve, ResultStatusEnumeration,
            UniqueIdentifier,
        },
    },
};

use crate::{
    config::ServerParams, result::KResult, tests::test_utils::https_clap_config, KMSServer,
};

#[tokio::test]
async fn test_kmip_messages() -> KResult<()> {
    // cosmian_logger::log_utils::log_init("info,hyper=info,reqwest=info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(clap_config)?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let ec_create_request =
        create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519)?;

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
        response.items[2].result_reason,
        Some(ErrorReason::Item_Not_Found)
    );
    assert_eq!(
        response.items[2].result_message,
        Some(
            "Get Key: no available key found (must be an active symmetric key or private key) for \
             object identifier id_12345"
                .to_owned()
        )
    );
    assert!(response.items[2].response_payload.is_none());
    Ok(())
}
