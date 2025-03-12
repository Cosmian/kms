use cosmian_kmip::kmip_2_1::{
    extra::tagging::EMPTY_TAGS,
    kmip_messages::{RequestMessageBatchItem, RequestMessage, RequestMessageHeader, ResponseMessage},
    kmip_operations::Operation,
    kmip_types::{OperationEnumeration, ProtocolVersion, ResultStatusEnumeration},
};
use cosmian_kms_client_utils::cover_crypt_utils::build_create_covercrypt_master_keypair_request;

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn integration_tests_bulk() -> KResult<()> {
    // cosmian_logger::log_init("trace,hyper=info,reqwest=info");
    let app = test_utils::test_app(None, None).await;

    // Parse the json access_structure file
    let access_structure = r#"{"Security Level::<":["Protected","Confidential","Top Secret::+"],"Department":["RnD","HR","MKG","FIN"]}"#;

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 2,
            ..Default::default()
        },
        batch_item: vec![
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

    let response: ResponseMessage = test_utils::post(&app, &request_message).await?;
    assert_eq!(response.batch_item.len(), 2);

    // 1. Create keypair
    assert_eq!(
        response.batch_item[0].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.batch_item[0].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.batch_item[0].response_payload else {
        panic!("not a create key pair response payload");
    };

    // 2. Create keypair
    assert_eq!(
        response.batch_item[1].operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(
        response.batch_item[1].result_status,
        ResultStatusEnumeration::Success
    );
    let Some(Operation::CreateKeyPairResponse(_)) = &response.batch_item[1].response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}
