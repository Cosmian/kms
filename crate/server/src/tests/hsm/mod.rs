use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            ProtocolVersion, ResultStatusEnumeration, RevocationReason, RevocationReasonCode,
        },
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Destroy, Operation, Revoke},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;
use tracing::info;
const EMPTY_TAGS: [&str; 0] = [];

use crate::{
    config::ClapConfig, core::KMS, error::KmsError, result::KResult,
    tests::test_utils::https_clap_config,
};

#[cfg(not(feature = "fips"))]
mod ec_dek;
mod rsa_dek;
mod symmetric_dek;

/// The HSM simulator does not like tests in parallell,
/// so we run them sequentially from here
#[tokio::test]
async fn test_all() {
    log_init(option_env!("RUST_LOG"));

    info!("HSM: wrapped_symmetric_dek");
    symmetric_dek::test_wrapped_symmetric_dek().await.unwrap();
    info!("HSM: wrapped_rsa_dek");
    rsa_dek::test_wrapped_rsa_dek().await.unwrap();
    #[cfg(not(feature = "fips"))]
    {
        info!("HSM: wrapped_ec_dek");
        ec_dek::test_wrapped_ec_dek().await.unwrap();
    }
}

fn hsm_clap_config(owner: &str, kek: Option<String>) -> ClapConfig {
    let mut clap_config = https_clap_config();
    clap_config.hsm_model = "utimaco".to_owned();
    clap_config.hsm_admin = owner.to_owned();
    clap_config.hsm_slot = vec![0];
    clap_config.hsm_password = vec!["12345678".to_owned()];

    if let Some(kek) = kek {
        clap_config.key_encryption_key = Some(kek);
    }

    clap_config
}

async fn create_kek(kek_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    // create the key encryption key
    let create_request = symmetric_key_create_request(
        Some(UniqueIdentifier::TextString(kek_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response =
        send_message(kms.clone(), owner, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(kek_uid.to_owned())
    );
    Ok(())
}

async fn delete_key(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let destroy_request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        remove: true,
    };
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Destroy(destroy_request)],
    )
    .await?;
    let Operation::DestroyResponse(destroy_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        destroy_response.unique_identifier,
        UniqueIdentifier::TextString(key_uid.to_owned())
    );
    Ok(())
}

async fn revoke_key(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let revoke_request = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::Unspecified,
            revocation_message: Some("revoke".to_owned()),
        },
        compromise_occurrence_date: None,
    };
    let response =
        send_message(kms.clone(), owner, vec![Operation::Revoke(revoke_request)]).await?;
    let Operation::RevokeResponse(revoke_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        revoke_response.unique_identifier,
        UniqueIdentifier::TextString(key_uid.to_owned())
    );
    Ok(())
}

async fn send_message(
    kms: Arc<KMS>,
    owner: &str,
    operations: Vec<Operation>,
) -> KResult<Vec<Operation>> {
    let num_ops = i32::try_from(operations.len())?;
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: num_ops,
            ..Default::default()
        },
        batch_item: operations
            .into_iter()
            .map(|op| RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(op)))
            .collect(),
    };

    let response = kms.message(request, owner, None).await?;
    assert_eq!(response.response_header.batch_count, num_ops);

    response
        .batch_item
        .into_iter()
        .map(|bi| {
            let ResponseMessageBatchItemVersioned::V21(bi) = bi else {
                return Err(KmsError::ServerError("invalid response".to_owned()))
            };
            if bi.result_status != ResultStatusEnumeration::Success {
                return Err(KmsError::ServerError(format!(
                    "operation failed: {:?}",
                    bi.result_message
                )));
            }
            bi.response_payload
                .ok_or_else(|| KmsError::ServerError("operation not found".to_owned()))
        })
        .collect::<KResult<Vec<Operation>>>()
}
