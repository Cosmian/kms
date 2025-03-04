use cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_messages::{Message, MessageBatchItem, MessageHeader, MessageResponse},
    kmip_operations::Operation,
    kmip_types::{OperationEnumeration, ProtocolVersion, ResultStatusEnumeration},
};
use cosmian_kms_crypto::crypto::cover_crypt::kmip_requests::build_create_covercrypt_master_keypair_request;

use crate::{result::KResult, tests::test_utils};
#[tokio::test]
async fn integration_tests_bulk() -> KResult<()> {
    // cosmian_logger::log_init("trace,hyper=info,reqwest=info");
    let app = test_utils::test_app(None).await;

    // Parse the json access_structure file
    let access_structure = "TEST";
    let request_message = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 2,
            ..Default::default()
        },
        items: vec![
            MessageBatchItem::new(Operation::CreateKeyPair(
                build_create_covercrypt_master_keypair_request(
                    access_structure,
                    EMPTY_TAGS,
                    false,
                )?,
            )),
            MessageBatchItem::new(Operation::CreateKeyPair(
                build_create_covercrypt_master_keypair_request(
                    access_structure,
                    EMPTY_TAGS,
                    false,
                )?,
            )),
        ],
    };

    let response: MessageResponse = test_utils::post(&app, &request_message).await?;
    assert_eq!(response.items.len(), 2);

    // 1. Create keypair
    assert_eq!(
        response.items[0].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.items[0].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[0].response_payload else {
        panic!("not a create key pair response payload");
    };

    // 2. Create keypair
    assert_eq!(
        response.items[1].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.items[1].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.items[1].response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}
