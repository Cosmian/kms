mod delete;
mod get;
mod set;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub use delete::DeleteAttributesAction;
pub use get::GetAttributesAction;
pub use set::{SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli};

use crate::error::result::CliResult;

/// Get/Set/Delete the KMIP object attributes.
#[derive(Subcommand)]
pub enum AttributesCommands {
    Get(GetAttributesAction),
    Set(SetAttributesAction),
    Delete(DeleteAttributesAction),
}

impl AttributesCommands {
    /// Process the Attributes commands action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client instance used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the version query fails or if there is an issue writing to the console.
    pub async fn process(&self, client_connector: &KmsClient) -> CliResult<()> {
        match self {
            Self::Get(action) => action.process(client_connector).await,
            Self::Set(action) => action.process(client_connector).await,
            Self::Delete(action) => action.process(client_connector).await,
        }
    }
}
