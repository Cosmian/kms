use clap::Subcommand;
use cosmian_client::{RestClient, RestClientConfig};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;

use super::{
    datasets::DatasetsAction,
    encrypt_and_index::EncryptAndIndexAction,
    findex::{insert_or_delete::InsertOrDeleteAction, search::SearchAction},
    login::LoginAction,
    logout::LogoutAction,
    permissions::PermissionsAction,
    search_and_decrypt::SearchAndDecryptAction,
    version::ServerVersionAction,
};
use crate::error::result::CosmianResult;

#[derive(Subcommand)]
pub enum FindexActions {
    /// Create new indexes
    Index(InsertOrDeleteAction),
    EncryptAndIndex(EncryptAndIndexAction),
    Search(SearchAction),
    SearchAndDecrypt(SearchAndDecryptAction),

    /// Delete indexed keywords
    Delete(InsertOrDeleteAction),

    #[command(subcommand)]
    Permissions(PermissionsAction),

    #[command(subcommand)]
    Datasets(DatasetsAction),

    Login(LoginAction),
    Logout(LogoutAction),

    ServerVersion(ServerVersionAction),
}

impl FindexActions {
    /// Actions that can be performed on the Findex server such as:
    /// - indexing, searching with or without datasets-encryption (indexes are always encrypted),
    /// - permissions management,
    /// - datasets management,
    /// - login and logout,
    ///
    /// # Errors
    /// Returns an error if the action fails
    #[allow(clippy::print_stdout)]
    pub async fn run(
        &self,
        findex_client: RestClient,
        kms_client: KmsClient,
        findex_config: RestClientConfig,
    ) -> CosmianResult<RestClientConfig> {
        match self {
            // actions that don't edit the configuration
            Self::Datasets(action) => {
                println!("{}", action.run(findex_client).await?);
                Ok(findex_config)
            }
            Self::Permissions(action) => {
                println!("{}", action.run(findex_client).await?);
                Ok(findex_config)
            }
            Self::ServerVersion(action) => {
                println!("{}", action.run(findex_client).await?);
                Ok(findex_config)
            }
            Self::Delete(action) => {
                println!("{}", action.delete(findex_client, kms_client).await?);
                Ok(findex_config)
            }
            Self::Index(action) => {
                println!("{}", action.insert(findex_client, kms_client).await?);
                Ok(findex_config)
            }
            Self::Search(action) => {
                println!("{}", action.run(findex_client, kms_client).await?);
                Ok(findex_config)
            }
            Self::EncryptAndIndex(action) => {
                println!("{}", action.run(findex_client, &kms_client).await?);
                Ok(findex_config)
            }
            Self::SearchAndDecrypt(action) => {
                let res = action.run(findex_client, &kms_client).await?;
                println!("Decrypted records: {res:?}");
                Ok(findex_config)
            }

            // actions that edit the configuration
            Self::Login(action) => action.run(findex_config).await,
            Self::Logout(action) => action.run(findex_config),
        }
    }
}
