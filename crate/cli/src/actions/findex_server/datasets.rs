use std::{collections::HashMap, error::Error};

use base64::{engine::general_purpose, Engine};
use clap::Parser;
use cosmian_findex_client::RestClient;
use cosmian_findex_structs::EncryptedEntries;
use uuid::Uuid;

use crate::error::{
    result::{CosmianResult, CosmianResultHelper},
    CosmianError,
};

/// Manage encrypted datasets
#[derive(Parser, Debug)]
pub enum DatasetsAction {
    Add(AddEntries),
    Delete(DeleteEntries),
    Get(GetEntries),
}

impl DatasetsAction {
    /// Processes the Datasets action.
    ///
    /// # Errors
    ///
    /// Returns an error if one of Add, Delete of Get actions fails
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        match self {
            Self::Add(action) => action.run(rest_client).await,
            Self::Delete(action) => action.run(rest_client).await,
            Self::Get(action) => action
                .run(rest_client)
                .await
                .map(|entries| entries.to_string()),
        }
    }
}

/// Add datasets entries.
#[derive(Parser, Debug)]
pub struct AddEntries {
    /// The index ID
    #[clap(long, required = true)]
    pub index_id: Uuid,

    /// The entries to add under the format `KEY=VALUE` where:
    /// - `KEY` is a UUID
    /// - `VALUE` is a base64 encoded string
    ///
    /// Can be repeated multiple times
    #[arg(short = 'D', value_parser = parse_key_val::<Uuid, String>)]
    pub entries: Vec<(Uuid, String)>,
}

/// Parse a single key-value pair
fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

impl AddEntries {
    /// Runs the `AddEntries` action.
    ///
    /// # Errors
    /// Returns an error if the query execution on the Findex server fails.
    /// Returns an error if the base64 decoding fails.
    /// Returns an error if the UUID parsing fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        let encrypted_entries = self.entries.iter().try_fold(
            HashMap::with_capacity(self.entries.len()),
            |mut acc, (key, value)| {
                let decoded_value = general_purpose::STANDARD.decode(value)?;
                acc.insert(*key, decoded_value);
                Ok::<_, CosmianError>(acc)
            },
        )?;

        let response = rest_client
            .add_entries(&self.index_id, &EncryptedEntries::from(encrypted_entries))
            .await
            .with_context(|| "Can't execute the add entries query on the findex server")?;

        Ok(response.to_string())
    }
}

/// Delete datasets entries using corresponding entries UUID.
#[derive(Parser, Debug)]
pub struct DeleteEntries {
    /// The index ID
    #[clap(long, required = true)]
    pub index_id: Uuid,

    /// The entries UUIDs to delete
    #[clap(long, required = true)]
    pub uuids: Vec<Uuid>,
}

impl DeleteEntries {
    /// Runs the `DeleteEntries` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<String> {
        let response = rest_client
            .delete_entries(&self.index_id, &self.uuids)
            .await
            .with_context(|| "Can't execute the delete entries query on the findex server")?;

        Ok(response.success)
    }
}

/// Return datasets entries matching given UUID.
#[derive(Parser, Debug)]
pub struct GetEntries {
    /// The index id
    #[clap(long, required = true)]
    pub index_id: Uuid,

    /// The entries uuids
    #[clap(long, required = true)]
    pub uuids: Vec<Uuid>,
}

impl GetEntries {
    /// Runs the `GetEntries` action.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the Findex server fails.
    /// Returns an error if the UUID parsing fails.
    pub async fn run(&self, rest_client: RestClient) -> CosmianResult<EncryptedEntries> {
        let encrypted_entries = rest_client
            .get_entries(&self.index_id, &self.uuids)
            .await
            .with_context(|| "Can't execute the get entries query on the findex server")?;

        Ok(encrypted_entries)
    }
}
