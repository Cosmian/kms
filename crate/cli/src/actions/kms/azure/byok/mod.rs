mod import_kek;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::{actions::kms::azure::byok::import_kek::ImportKekAction, error::result::KmsCliResult};

/// Azure BYOK commands.
/// Specifications Doc: https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification
#[derive(Subcommand)]
pub enum ByokCommands {
    Import(ImportKekAction),
    // Export(crate::actions::kms::google::identities::list_identities::ListIdentitiesAction),
}

impl ByokCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Import(action) => action.run(kms_rest_client),
            // Self::Export(action) => action.run(kms_rest_client).await,
        }
    }
}
