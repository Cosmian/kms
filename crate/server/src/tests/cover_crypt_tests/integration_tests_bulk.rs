use cloudproof::reexport::cover_crypt::abe_policy::{DimensionBuilder, EncryptionHint, Policy};
use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        extra::tagging::EMPTY_TAGS, kmip_messages::RequestMessageBatchItem,
        kmip_operations::Operation, kmip_types::OperationEnumeration,
    },
};
use cosmian_kms_crypto::crypto::cover_crypt::kmip_requests::build_create_covercrypt_master_keypair_request;
use cosmian_logger::log_init;

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn integration_tests_bulk() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let app = test_utils::test_app(None).await;

    let mut policy = Policy::new();
    policy.add_dimension(DimensionBuilder::new(
        "Department",
        vec![
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
        ],
        false,
    ))?;
    policy.add_dimension(DimensionBuilder::new(
        "Level",
        vec![
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 2,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(build_create_covercrypt_master_keypair_request(
                    &policy, EMPTY_TAGS, false,
                )?),
            )),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                Operation::CreateKeyPair(build_create_covercrypt_master_keypair_request(
                    &policy, EMPTY_TAGS, false,
                )?),
            )),
        ],
    };

    let response: ResponseMessage = test_utils::post_2_1(&app, &request_message).await?;
    assert_eq!(response.batch_item.len(), 2);

    // 1. Create keypair
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("not a create key pair response payload");
    };
    assert_eq!(
        batch_item.operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::CreateKeyPairResponse(_)) = &batch_item.response_payload else {
        panic!("not a create key pair response payload");
    };

    // 2. Create keypair
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[1] else {
        panic!("not a create key pair response payload");
    };
    assert_eq!(
        batch_item.operation,
        Some(OperationEnumeration::CreateKeyPair)
    );
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::CreateKeyPairResponse(_)) = &batch_item.response_payload else {
        panic!("not a create key pair response payload");
    };

    Ok(())
}
