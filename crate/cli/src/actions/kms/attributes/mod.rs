mod delete;
mod get;
mod set;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub use delete::DeleteAttributesAction;
pub use get::GetAttributesAction;
pub use set::{SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli};

use crate::error::result::CosmianResult;

/// Get/Set/Delete the KMIP object attributes.
#[derive(Subcommand)]
pub enum AttributesCommands {
    Get(GetAttributesAction),
    Set(SetAttributesAction),
    Delete(DeleteAttributesAction),
}

#[cfg(test)]
pub use cosmian_kms_client::reexport::cosmian_kms_client_utils::attributes_utils::CLinkType;
#[cfg(test)]
pub use set::CCryptographicAlgorithm;

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
    pub async fn process(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        match self {
            Self::Get(action) => action.process(client_connector).await,
            Self::Set(action) => action.process(client_connector).await,
            Self::Delete(action) => action.process(client_connector).await,
        }
    }
}
