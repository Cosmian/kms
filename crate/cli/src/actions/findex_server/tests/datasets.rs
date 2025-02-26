use crate::{
    actions::findex_server::datasets::{AddEntries, DeleteEntries, GetEntries},
    error::result::CosmianResult,
};
use base64::{engine::general_purpose, Engine};
use cosmian_client::RestClient;
use cosmian_findex_structs::EncryptedEntries;
use cosmian_logger::log_init;
use std::ops::Deref;
use test_findex_server::start_default_test_findex_server;
use uuid::Uuid;

async fn dataset_add_entries(
    rest_client: RestClient,
    index_id: &Uuid,
    entries: Vec<(Uuid, String)>,
) -> CosmianResult<()> {
    // we don't need the output of this in the test, hence it's discarded
    AddEntries {
        index_id: *index_id,
        entries,
    }
    .run(rest_client)
    .await?;
    Ok(())
}

async fn dataset_delete_entries(
    rest_client: RestClient,
    index_id: &Uuid,
    uuids: Vec<Uuid>,
) -> CosmianResult<()> {
    DeleteEntries {
        index_id: *index_id,
        uuids,
    }
    .run(rest_client)
    .await?;
    Ok(())
}

async fn dataset_get_entries(
    rest_client: RestClient,
    index_id: &Uuid,
    uuids: Vec<Uuid>,
) -> CosmianResult<EncryptedEntries> {
    GetEntries {
        index_id: *index_id,
        uuids,
    }
    .run(rest_client)
    .await
}

#[tokio::test]
pub(crate) async fn test_datasets() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_findex_server().await;
    let owner_rest_client = RestClient::new(&ctx.owner_client_conf.clone())?;

    let index_id = Uuid::new_v4();

    // Dataset entries IDs
    let entries_number = 100;
    let encrypted_entries: Vec<(Uuid, String)> = (1..=entries_number)
        .map(|i| {
            let entry_id = Uuid::new_v4();
            let data = general_purpose::STANDARD.encode(format!("entry{i}"));
            (entry_id, data)
        })
        .collect();

    let uuids: Vec<Uuid> = encrypted_entries.iter().map(|(uuid, _)| *uuid).collect();

    // Add entries to the dataset
    dataset_add_entries(
        owner_rest_client.clone(),
        &index_id,
        encrypted_entries.clone(),
    )
    .await?;

    // Get the added entries from the dataset
    let added_entries =
        dataset_get_entries(owner_rest_client.clone(), &index_id, uuids.clone()).await?;
    assert_eq!(added_entries.len(), entries_number);

    dataset_delete_entries(
        owner_rest_client.clone(),
        &index_id,
        added_entries.get_uuids().deref().to_owned(),
    )
    .await?;

    // Get the added entries from the dataset
    let deleted_entries = dataset_get_entries(owner_rest_client, &index_id, uuids).await?;
    assert_eq!(deleted_entries.len(), 0);

    Ok(())
}
