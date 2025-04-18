use std::path::PathBuf;

use cosmian_findex::test_utils::{
    gen_seed, test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
};
use cosmian_findex_client::RestClient;
use cosmian_findex_structs::{CUSTOM_WORD_LENGTH, Value};
use cosmian_kms_client::KmsClient;
use cosmian_logger::log_init;
use test_findex_server::{
    start_default_test_findex_server, start_default_test_findex_server_with_cert_auth,
};
use test_kms_server::start_default_test_kms_server;
use tracing::trace;
use uuid::Uuid;

use super::utils::HUGE_DATASET;
use crate::{
    actions::findex_server::{
        findex::{
            insert_or_delete::InsertOrDeleteAction, parameters::FindexParameters,
            search::SearchAction,
        },
        tests::{
            findex::utils::{SMALL_DATASET, create_encryption_layer, insert_search_delete},
            permissions::create_index_id,
            search_options::SearchOptions,
        },
    },
    error::result::CosmianResult,
};

pub(crate) fn findex_number_of_threads() -> Option<usize> {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        Some(1)
    } else {
        None
    }
}

#[tokio::test]
pub(crate) async fn test_findex_no_auth() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server().await;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;
    let findex_parameters = FindexParameters::new(
        Uuid::new_v4(),
        &kms_client,
        true,
        findex_number_of_threads(),
    )
    .await?;

    // Search 2 entries in a small dataset. Expect 2 results.
    let search_options = SearchOptions {
        dataset_path: SMALL_DATASET.into(),
        keywords: vec!["Southborough".to_owned()],
        expected_results: {
            vec![Value::from("SouthboroughMAUnited States9686")]
                .into_iter()
                .collect()
        },
    };
    insert_search_delete(
        &findex_parameters,
        &ctx.owner_client_conf,
        search_options,
        kms_client,
    )
    .await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_findex_local_encryption() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server().await;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;
    let findex_parameters = FindexParameters::new(
        Uuid::new_v4(),
        &kms_client,
        false,
        findex_number_of_threads(),
    )
    .await?;

    // Search 2 entries in a small dataset. Expect 2 results.
    let search_options = SearchOptions {
        dataset_path: SMALL_DATASET.into(),
        keywords: vec!["Southborough".to_owned()],
        expected_results: {
            vec![Value::from("SouthboroughMAUnited States9686")]
                .into_iter()
                .collect()
        },
    };
    insert_search_delete(
        &findex_parameters,
        &ctx.owner_client_conf,
        search_options,
        kms_client,
    )
    .await?;
    Ok(())
}

async fn run_huge_dataset_test(use_remote_crypto: bool) -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server().await;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;
    let findex_parameters = FindexParameters::new(
        Uuid::new_v4(),
        &kms_client,
        use_remote_crypto,
        findex_number_of_threads(),
    )
    .await?;

    // Search 1 entry in a huge dataset
    let search_options = SearchOptions {
        dataset_path: HUGE_DATASET.into(),
        keywords: vec![
            "BDCQ.SEA1AA".to_owned(),
            "2011.06".to_owned(),
            "80078".to_owned(),
        ],
        expected_results: {
            vec![Value::from(
                "BDCQ.SEA1AA2011.0680078FNumber0Business Data Collection - BDCIndustry by \
                 employment variableFilled jobsAgriculture, Forestry and FishingActual",
            )]
            .into_iter()
            .collect()
        },
    };
    insert_search_delete(
        &findex_parameters,
        &ctx.owner_client_conf,
        search_options,
        kms_client,
    )
    .await
}

#[ignore]
#[tokio::test]
pub(crate) async fn test_findex_huge_dataset_remote_crypto() -> CosmianResult<()> {
    run_huge_dataset_test(true).await
}

#[ignore]
#[tokio::test]
pub(crate) async fn test_findex_huge_dataset_local_crypto() -> CosmianResult<()> {
    run_huge_dataset_test(false).await
}

#[tokio::test]
pub(crate) async fn test_findex_cert_auth() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server_with_cert_auth().await;
    let owner_rest_client = RestClient::new(&ctx.owner_client_conf.clone())?;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;

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

    let findex_parameters =
        FindexParameters::new(index_id, &kms_client, true, findex_number_of_threads()).await?;

    insert_search_delete(
        &findex_parameters,
        &ctx.owner_client_conf,
        search_options,
        kms_client,
    )
    .await?;

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_findex_searching_with_bad_key() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server().await;

    let rest_client = RestClient::new(&ctx.owner_client_conf.clone())?;
    let ctx_kms = start_default_test_kms_server().await;
    let kms_client = KmsClient::new_with_config(ctx_kms.owner_client_conf.kms_config.clone())?;

    let index_id = create_index_id(rest_client.clone()).await?;
    trace!("index_id: {index_id}");

    // Search 2 entries in a small dataset. Expect 2 results.
    let search_options = SearchOptions {
        dataset_path: SMALL_DATASET.into(),
        keywords: vec!["Southborough".to_owned()],
        expected_results: {
            vec![Value::from("SouthboroughMAUnited States9686")]
                .into_iter()
                .collect()
        },
    };
    let findex_parameters = FindexParameters::new(
        Uuid::new_v4(),
        &kms_client,
        true,
        findex_number_of_threads(),
    )
    .await?;

    // Index the dataset
    InsertOrDeleteAction {
        findex_parameters: findex_parameters.clone(),
        csv: PathBuf::from(&search_options.dataset_path),
    }
    .insert(rest_client.clone(), kms_client.clone())
    .await?;

    // But change the findex keys
    // Ensures searching returns no result
    let search_results = SearchAction {
        findex_parameters: FindexParameters::new(
            Uuid::new_v4(),
            &kms_client,
            true,
            findex_number_of_threads(),
        )
        .await?,
        keyword: search_options.keywords.clone(),
    }
    .run(rest_client, kms_client)
    .await?;
    assert!(search_results.is_empty());
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_findex_sequential_read_write() -> CosmianResult<()> {
    log_init(None);

    test_single_write_and_read::<CUSTOM_WORD_LENGTH, _>(
        &create_encryption_layer::<CUSTOM_WORD_LENGTH>().await?,
        gen_seed(),
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn test_findex_sequential_wrong_guard() -> CosmianResult<()> {
    test_wrong_guard(
        &create_encryption_layer::<CUSTOM_WORD_LENGTH>().await?,
        gen_seed(),
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn test_findex_concurrent_read_write() -> CosmianResult<()> {
    test_guarded_write_concurrent(
        &create_encryption_layer::<CUSTOM_WORD_LENGTH>().await?,
        gen_seed(),
        Some(100),
    )
    .await;
    Ok(())
}
