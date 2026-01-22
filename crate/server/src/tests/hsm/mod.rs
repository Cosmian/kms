use std::{ops::Add, sync::Arc};

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Export, Import},
    requests::create_rsa_key_pair_request,
};
use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
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
        kmip_operations::{Destroy, Locate, Operation, Revoke},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::{debug, info, log_init};
use uuid::Uuid;

const EMPTY_TAGS: [&str; 0] = [];

use crate::{
    config::ClapConfig,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::test_helpers::{get_hsm_model, get_hsm_password, get_hsm_slot_id},
        test_utils::https_clap_config,
    },
};

#[cfg(feature = "non-fips")]
mod ec_dek;
mod rsa_dek;
mod search;
mod secret_data_dek;
mod symmetric_dek;
mod test_helpers;

/// The HSM simulator does not like tests in parallel,
/// so we run them sequentially from here
#[tokio::test]
#[ignore = "Requires a working HSM setup"]
async fn test_hsm_all() {
    log_init(option_env!("RUST_LOG"));
    info!("HSM: find");
    search::test_object_search().await.unwrap();

    info!("HSM: wrapped_symmetric_dek");
    // Box::pin are needed to conform to clippy::large_futures lint
    Box::pin(symmetric_dek::test_wrapped_symmetric_dek())
        .await
        .unwrap();
    info!("HSM: wrapped_secret_data");
    Box::pin(secret_data_dek::test_wrapped_secret_data())
        .await
        .unwrap();
    info!("HSM: wrapped_rsa_dek");
    Box::pin(rsa_dek::test_wrapped_rsa_dek()).await.unwrap();
    #[cfg(feature = "non-fips")]
    {
        info!("HSM: wrapped_ec_dek");
        Box::pin(ec_dek::test_wrapped_ec_dek()).await.unwrap();
    }
}

fn hsm_clap_config(owner: &str, kek_id: Option<Uuid>) -> KResult<ClapConfig> {
    let mut clap_config = https_clap_config();
    let model: Option<String> = get_hsm_model();
    let unwrapped_model = model.unwrap_or_else(|| "default".to_owned());

    if unwrapped_model == "default" {
        // For backwards compatible with existing tests.
        clap_config.hsm.hsm_model = "utimaco".to_owned();
        clap_config.hsm.hsm_admin = owner.to_owned();
        clap_config.hsm.hsm_slot = vec![0];
        clap_config.hsm.hsm_password = vec!["12345678".to_owned()];
    } else {
        let user_password = get_hsm_password()?;
        let slot = get_hsm_slot_id()?;
        clap_config.hsm.hsm_admin = owner.to_owned();
        clap_config.hsm.hsm_slot = vec![slot];
        clap_config.hsm.hsm_password = vec![user_password];
        if unwrapped_model == "utimaco" {
            clap_config.hsm.hsm_model = "utimaco".to_owned();
        } else if unwrapped_model == "softhsm2" {
            clap_config.hsm.hsm_model = "softhsm2".to_owned();
        } else if unwrapped_model == "smartcardhsm" {
            clap_config.hsm.hsm_model = "smartcardhsm".to_owned();
        } else if unwrapped_model == "proteccio" {
            clap_config.hsm.hsm_model = "proteccio".to_owned();
        } else if unwrapped_model == "crypt2pay" {
            clap_config.hsm.hsm_model = "crypt2pay".to_owned();
        } else if unwrapped_model == "other" {
            clap_config.hsm.hsm_model = "other".to_owned();
        } else {
            return Err(KmsError::Default(
                "The provided HSM model is unknown".to_owned(),
            ));
        }
    }
    info!("Configured HSM tests for {unwrapped_model}");

    if let Some(kek_id) = kek_id {
        clap_config.key_encryption_key = Some(as_hsm_uid!(clap_config.hsm.hsm_slot[0], kek_id));
    }

    Ok(clap_config)
}

async fn create_kek(kek_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    create_sym_key(kek_uid, owner, kms).await?;
    Ok(())
}

async fn create_sym_key(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    // create the key encryption key
    let create_request = symmetric_key_create_request(
        Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response =
        send_message(kms.clone(), owner, vec![Operation::Create(create_request)]).await?;
    let Operation::CreateResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        create_response.unique_identifier,
        UniqueIdentifier::TextString(key_uid.to_owned())
    );
    Ok(())
}

async fn create_key_pair(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    // create the key encryption key
    let create_request = create_rsa_key_pair_request(
        Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        EMPTY_TAGS,
        2048,
        false,
        None,
    )?;
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::CreateKeyPair(Box::from(create_request))],
    )
    .await?;
    let Operation::CreateKeyPairResponse(create_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert!(
        create_response.private_key_unique_identifier
            == UniqueIdentifier::TextString(key_uid.to_owned())
    );
    assert!(
        create_response.public_key_unique_identifier
            == UniqueIdentifier::TextString(key_uid.to_owned().add("_pk"))
    );
    Ok(())
}

async fn locate_keys(
    owner: &str,
    kms: &Arc<KMS>,
    attributes: Option<Attributes>,
) -> KResult<Vec<UniqueIdentifier>> {
    let locate_request = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: attributes.unwrap_or_default(),
    };
    // create the key encryption key
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Locate(Box::new(locate_request))],
    )
    .await?;
    let Operation::LocateResponse(locate_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    Ok(locate_response
        .unique_identifier
        .clone()
        .unwrap_or_default())
}

async fn import_object(
    kms: &Arc<KMS>,
    owner: &str,
    object_id: &str,
    object: &Object,
    object_type: ObjectType,
) -> KResult<UniqueIdentifier> {
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(object_id.to_owned()),
        object_type,
        attributes: Attributes {
            object_type: Some(object_type),
            ..Default::default()
        },
        replace_existing: None,
        key_wrap_type: None,
        object: object.clone(),
    };

    let create_response = kms.import(import_request, owner, None).await?;
    Ok(create_response.unique_identifier)
}

async fn export_object(kms: &Arc<KMS>, owner: &str, object_id: &str) -> KResult<Object> {
    let export_request = Export {
        unique_identifier: Some(UniqueIdentifier::TextString(object_id.to_owned())),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        key_wrapping_specification: None,
    };

    let export_response = kms.export(export_request, owner).await?;
    Ok(export_response.object)
}

async fn delete_key(key_uid: &str, owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let destroy_request = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid.to_owned())),
        remove: true,
        cascade: true,
    };
    let response = send_message(
        kms.clone(),
        owner,
        vec![Operation::Destroy(destroy_request)],
    )
    .await?;
    let Operation::DestroyResponse(destroy_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
    };
    assert_eq!(
        destroy_response.unique_identifier,
        UniqueIdentifier::TextString(key_uid.to_owned())
    );
    Ok(())
}

async fn delete_all_keys(owner: &str, kms: &Arc<KMS>) -> KResult<()> {
    let found_keys = locate_keys(owner, kms, None).await?;
    debug!("Found {} keys. Removing...", found_keys.len());
    for found_key in found_keys {
        let Some(key_string) = found_key.as_str() else {
            continue;
        };
        delete_key(key_string, owner, kms).await?;
    }
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
        cascade: true,
    };
    let response =
        send_message(kms.clone(), owner, vec![Operation::Revoke(revoke_request)]).await?;
    let Operation::RevokeResponse(revoke_response) = &response[0] else {
        return Err(KmsError::ServerError("invalid response".to_owned()));
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

    let response = kms.message(request, owner).await?;
    assert_eq!(response.response_header.batch_count, num_ops);

    response
        .batch_item
        .into_iter()
        .map(|bi| {
            let ResponseMessageBatchItemVersioned::V21(bi) = bi else {
                return Err(KmsError::ServerError("invalid response".to_owned()));
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
