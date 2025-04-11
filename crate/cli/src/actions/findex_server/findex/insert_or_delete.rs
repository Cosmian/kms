use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::PathBuf,
};

use clap::Parser;
use cosmian_findex::Value;
use cosmian_findex_client::RestClient;
use cosmian_findex_structs::{CUSTOM_WORD_LENGTH, Keyword, Keywords};
use cosmian_kms_client::KmsClient;
use tracing::trace;

use super::parameters::FindexParameters;
use crate::{
    actions::findex_server::findex::findex_instance::FindexInstance, error::result::CosmianResult,
};

#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct InsertOrDeleteAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,
    /// The path to the CSV file containing the data to index
    #[clap(long)]
    pub(crate) csv: PathBuf,
}

impl InsertOrDeleteAction {
    /// First, converts a CSV file to a hashmap where the keys are keywords and
    /// the values are sets of indexed values (Data). Then, inserts or deletes
    /// using the Findex instance.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The CSV file cannot be opened.
    /// - There is an error reading the CSV records.
    /// - There is an error converting the CSV records to the expected data
    ///   types.
    /// - The Findex instance cannot be instantiated.
    /// - The Findex instance cannot insert or delete the data.
    /// - The semaphore cannot acquire a permit.
    async fn insert_or_delete(
        &self,
        rest_client: RestClient,
        kms_client: KmsClient,
        is_insert: bool,
    ) -> CosmianResult<Keywords> {
        let file = File::open(&self.csv)?;

        let bindings = csv::Reader::from_reader(file).byte_records().fold(
            HashMap::new(),
            |mut acc: HashMap<Keyword, HashSet<Value>>, result| {
                if let Ok(record) = result {
                    let indexed_value = Value::from(record.as_slice());
                    // Extract keywords from the record and associate them with the indexed values
                    // Index the lowercase only
                    for keyword in record
                        .iter()
                        .map(|x| Keyword::from(x.to_ascii_lowercase().as_slice()))
                    {
                        acc.entry(keyword)
                            .or_default()
                            .insert(indexed_value.clone());
                    }
                }
                acc
            },
        );

        let findex_instance = FindexInstance::<CUSTOM_WORD_LENGTH>::instantiate_findex(
            rest_client,
            kms_client,
            self.findex_parameters.clone().instantiate_keys()?,
        )
        .await?;

        let written_keywords = findex_instance
            .insert_or_delete(bindings, is_insert, self.findex_parameters.num_threads)
            .await?;
        let operation_name = if is_insert { "Indexing" } else { "Deleting" };

        trace!("{operation_name} is done. Keywords: {written_keywords}");
        Ok(written_keywords)
    }

    /// Insert new indexes
    ///
    /// # Errors
    /// - If insert new indexes fails
    pub async fn insert(
        &self,
        rest_client: RestClient,
        kms_client: KmsClient,
    ) -> CosmianResult<Keywords> {
        Self::insert_or_delete(self, rest_client, kms_client, true).await
    }

    /// Deletes indexes
    ///
    /// # Errors
    /// - If deleting indexes fails
    pub async fn delete(
        &self,
        rest_client: RestClient,
        kms_client: KmsClient,
    ) -> CosmianResult<Keywords> {
        Self::insert_or_delete(self, rest_client, kms_client, false).await
    }
}
