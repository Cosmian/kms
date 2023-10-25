use cloudproof::reexport::cover_crypt::abe_policy::{EncryptionHint, Policy, PolicyAxis};
use cosmian_kmip::kmip::{
    kmip_messages::{Message, MessageBatchItem, MessageHeader, MessageResponse},
    kmip_operations::Operation,
    kmip_types::{OperationEnumeration, ProtocolVersion, ResultStatusEnumeration},
};
use cosmian_kms_utils::{
    crypto::cover_crypt::kmip_requests::build_create_master_keypair_request, tagging::EMPTY_TAGS,
};

use crate::{result::KResult, tests::test_utils};

#[actix_web::test]
async fn integration_tests_bulk() -> KResult<()> {
    // cosmian_logger::log_utils::log_init("trace,hyper=info,reqwest=info");

    let app = test_utils::test_app().await;

    let mut policy = Policy::new(10);
    policy.add_axis(PolicyAxis::new(
        "Department",
        vec![
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
        ],
        false,
    ))?;
    policy.add_axis(PolicyAxis::new(
        "Level",
        vec![
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    ))?;

    let request_message = Message {
        header: MessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 2,
            maximum_response_size: None,
            client_correlation_value: None,
            server_correlation_value: None,
            asynchronous_indicator: None,
            attestation_capable_indicator: None,
            attestation_type: None,
            authentication: None,
            batch_error_continuation_option: None,
            batch_order_option: None,
            timestamp: None,
        },
        items: vec![
            MessageBatchItem {
                operation: OperationEnumeration::CreateKeyPair,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::CreateKeyPair(build_create_master_keypair_request(
                    &policy, EMPTY_TAGS,
                )?),
                message_extension: None,
            },
            MessageBatchItem {
                operation: OperationEnumeration::CreateKeyPair,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::CreateKeyPair(build_create_master_keypair_request(
                    &policy, EMPTY_TAGS,
                )?),
                message_extension: None,
            },
        ],
    };

    let response: MessageResponse = test_utils::post(&app, &request_message).await?;

    // tracing::trace!("{response:#?}");
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
