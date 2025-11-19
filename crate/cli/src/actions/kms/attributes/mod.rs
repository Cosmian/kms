mod delete;
mod get;
mod set;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub use delete::DeleteAttributesAction;
pub use get::GetAttributesAction;
pub(crate) use get::get_attributes;
pub use set::{SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli};

use crate::error::result::KmsCliResult;

/// Get/Set/Delete the KMIP object attributes.
#[derive(Subcommand)]
pub enum AttributesCommands {
    Get(GetAttributesAction),
    Set(SetAttributesAction),
    Delete(DeleteAttributesAction),
}

#[cfg(test)]
pub use cosmian_kms_client::reexport::cosmian_kms_client_utils::attributes_utils::CLinkType;
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
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Get(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Set(action) => action.process(kms_rest_client).await,
            Self::Delete(action) => action.process(kms_rest_client).await,
        }
    }
}
