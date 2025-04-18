use std::{ops::Deref, path::PathBuf};

use cosmian_findex_client::RestClient;
use cosmian_findex_structs::{Permission, Value};
use cosmian_kms_client::KmsClient;
use cosmian_logger::log_init;
use test_findex_server::start_default_test_findex_server_with_cert_auth;
use test_kms_server::start_default_test_kms_server;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    actions::findex_server::{
        findex::{
            insert_or_delete::InsertOrDeleteAction, parameters::FindexParameters,
            search::SearchAction,
        },
        tests::{
            findex::{
                basic::findex_number_of_threads,
                utils::{SMALL_DATASET, insert_search_delete},
            },
            permissions::{create_index_id, list_permissions, revoke_permission, set_permission},
            search_options::SearchOptions,
        },
    },
    error::result::CosmianResult,
};

#[tokio::test]
pub(crate) async fn test_findex_set_and_revoke_permission() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server_with_cert_auth().await;
    let owner_rest_client = RestClient::new(&ctx.owner_client_conf.clone())?;

    let search_options = SearchOptions {
        dataset_path: SMALL_DATASET.into(),
        keywords: vec!["Southborough".to_owned()],
        expected_results: {
            vec![Value::from("SouthboroughMAUnited States9686")]
                .into_iter()
                .collect()
        },
    };

    let index_id = create_index_id(owner_rest_client).await?;
    trace!("index_id: {index_id}");

    let owner_rest_client = RestClient::new(&ctx.owner_client_conf)?;
    let user_rest_client = RestClient::new(&ctx.user_client_conf)?;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;

    let findex_parameters =
        FindexParameters::new(index_id, &kms_client, true, findex_number_of_threads()).await?;

    // Index the dataset as admin
    InsertOrDeleteAction {
        findex_parameters: findex_parameters.clone(),
        csv: PathBuf::from(SMALL_DATASET),
    }
    .insert(owner_rest_client.clone(), kms_client.clone())
    .await?;

    // Set read permission to the client
    set_permission(
        owner_rest_client.clone(),
        "user.client@acme.com".to_owned(),
        index_id,
        Permission::Read,
    )
    .await?;

    // User can read...
    let search_results = SearchAction {
        findex_parameters: findex_parameters.clone(),
        keyword: search_options.keywords.clone(),
    }
    .run(user_rest_client.clone(), kms_client.clone())
    .await?;
    assert_eq!(
        search_options.expected_results,
        search_results.deref().clone()
    );

    // ... but not write
    InsertOrDeleteAction {
        findex_parameters: findex_parameters.clone(),
        csv: PathBuf::from(SMALL_DATASET),
    }
    .insert(user_rest_client.clone(), kms_client.clone())
    .await
    .unwrap_err();

    // Set write permission
    set_permission(
        owner_rest_client.clone(),
        "user.client@acme.com".to_owned(),
        index_id,
        Permission::Write,
    )
    .await?;

    let perm =
        list_permissions(owner_rest_client.clone(), "user.client@acme.com".to_owned()).await?;
    debug!("User permission: {:?}", perm);

    // User can read...
    let search_results = SearchAction {
        findex_parameters: findex_parameters.clone(),
        keyword: search_options.keywords.clone(),
    }
    .run(user_rest_client.clone(), kms_client.clone())
    .await?;
    assert_eq!(
        search_options.expected_results,
        search_results.deref().clone()
    );

    // ... and write
    InsertOrDeleteAction {
        findex_parameters: findex_parameters.clone(),
        csv: PathBuf::from(SMALL_DATASET),
    }
    .insert(user_rest_client.clone(), kms_client.clone())
    .await?;

    // Try to escalade privileges from `read` to `admin`
    set_permission(
        user_rest_client.clone(),
        "user.client@acme.com".to_owned(),
        index_id,
        Permission::Admin,
    )
    .await
    .unwrap_err();

    revoke_permission(
        owner_rest_client,
        "user.client@acme.com".to_owned(),
        index_id,
    )
    .await?;

    let _search_results = SearchAction {
        findex_parameters: findex_parameters.clone(),
        keyword: search_options.keywords.clone(),
    }
    .run(user_rest_client.clone(), kms_client.clone())
    .await
    .unwrap_err();

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_findex_no_permission() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server_with_cert_auth().await;

    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;
    let findex_parameters = FindexParameters::new(
        Uuid::new_v4(),
        &kms_client,
        true,
        findex_number_of_threads(),
    )
    .await?;

    let search_options = SearchOptions {
        dataset_path: SMALL_DATASET.into(),
        keywords: vec!["Southborough".to_owned()],
        expected_results: {
            vec![Value::from("SouthboroughMAUnited States9686")]
                .into_iter()
                .collect()
        },
    };

    assert!(
        insert_search_delete(
            &findex_parameters,
            &ctx.user_client_conf,
            search_options,
            kms_client
        )
        .await
        .is_err()
    );

    Ok(())
}
