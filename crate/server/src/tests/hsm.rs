use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Destroy, Operation},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;
use uuid::Uuid;

const EMPTY_TAGS: [&str; 0] = [];

use crate::{
    config::{ClapConfig, ServerParams},
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::test_utils::https_clap_config,
};

fn hsm_clap_config(owner: &str, kek: Option<String>) -> ClapConfig {
    let mut clap_config = https_clap_config();
    clap_config.hsm_model = "utimaco".to_string();
    clap_config.hsm_admin = owner.to_owned();
    clap_config.hsm_slot = vec![0];
    clap_config.hsm_password = vec!["12345678".to_owned()];

    if let Some(kek) = kek {
        clap_config.key_encryption_key = Some(kek);
    }

    clap_config
}

#[tokio::test]
async fn test_create_key() -> KResult<()> {
    log_init(Some("info,cosmian_kms_server=debug"));

    let kek_uid = format!("hsm::0::{}", Uuid::new_v4());
    let owner = Uuid::new_v4().to_string();
    let clap_config = hsm_clap_config(&owner, Some(kek_uid.clone()));

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // create the key encryption key
    let create_request = symmetric_key_create_request(
        Some(UniqueIdentifier::TextString(kek_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response =
        send_message(kms.clone(), &owner, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_reponse) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        create_reponse.unique_identifier,
        UniqueIdentifier::TextString(kek_uid.clone())
    );

    //Delete the key wrapping key
    let destroy_request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
        remove: true,
    };
    let response = send_message(
        kms.clone(),
        &owner,
        vec![Operation::Destroy(destroy_request)],
    )
    .await?;
    let Operation::DestroyResponse(destroy_reponse) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()))
    };
    assert_eq!(
        destroy_reponse.unique_identifier,
        UniqueIdentifier::TextString(kek_uid)
    );

    Ok(())
}

async fn send_message(
    kms: Arc<KMS>,
    owner: &str,
    operations: Vec<Operation>,
) -> KResult<Vec<Operation>> {
    let num_ops = operations.len() as i32;
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
