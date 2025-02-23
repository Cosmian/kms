use clap::Subcommand;
use cosmian_findex_cli::{
    reexports::cosmian_findex_client::{RestClient, RestClientConfig},
    CoreFindexActions,
};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;

use super::{encrypt_and_index::EncryptAndIndexAction, search_and_decrypt::SearchAndDecryptAction};
use crate::error::{result::CosmianResult, CosmianError};

#[derive(Subcommand)]
pub enum FindexActions {
    EncryptAndIndex(EncryptAndIndexAction),
    SearchAndDecrypt(SearchAndDecryptAction),
    #[clap(flatten)]
    Findex(CoreFindexActions),
}

impl FindexActions {
    /// Combine Findex with KMS encryption
    ///
    /// # Errors
    /// Returns an error if the action fails
    pub async fn run(
        &self,
        findex_rest_client: &mut RestClient,
        kms_rest_client: &KmsClient,
        findex_config: &mut RestClientConfig,
    ) -> CosmianResult<()> {
        match self {
            Self::Findex(action) => action
                .run(findex_rest_client, kms_rest_client.clone(), findex_config)
                .await
                .map_err(CosmianError::from),
            Self::EncryptAndIndex(action) => {
                action.run(findex_rest_client, kms_rest_client).await?;
                Ok(())
            }
            Self::SearchAndDecrypt(action) => {
                action.run(findex_rest_client, kms_rest_client).await?;
                Ok(())
            }
        }
    }
}
