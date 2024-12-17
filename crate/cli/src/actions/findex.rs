use clap::Subcommand;
use cosmian_findex_cli::{CoreFindexActions, reexports::cosmian_findex_client::FindexRestClient};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;

use super::{
    delete_datasets::DeleteDatasetAction, encrypt_and_index::EncryptAndIndexAction,
    search_and_decrypt::SearchAndDecryptAction,
};
use crate::error::{CosmianError, result::CosmianResult};

#[derive(Subcommand)]
pub enum FindexActions {
    EncryptAndIndex(EncryptAndIndexAction),
    SearchAndDecrypt(SearchAndDecryptAction),
    DeleteDataset(DeleteDatasetAction),
    #[clap(flatten)]
    Findex(CoreFindexActions),
}

impl FindexActions {
    /// Combine Findex with KMS encryption
    ///
    /// # Errors
    /// Returns an error if the action fails
    #[allow(clippy::future_not_send)]
    pub async fn run(
        &self,
        findex_rest_client: &mut FindexRestClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<()> {
        match self {
            Self::Findex(action) => action
                .run(findex_rest_client)
                .await
                .map_err(CosmianError::from),
            Self::EncryptAndIndex(action) => action.run(findex_rest_client, kms_rest_client).await,
            Self::SearchAndDecrypt(action) => action.run(findex_rest_client, kms_rest_client).await,
            Self::DeleteDataset(action) => action.run(findex_rest_client).await,
        }
    }
}
