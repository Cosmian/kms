mod export_byok;
mod import_kek;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::azure::byok::{export_byok::ExportByokAction, import_kek::ImportKekAction},
    error::result::KmsCliResult,
};

/// Azure BYOK support.
/// See: https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification
#[derive(Subcommand)]
pub enum ByokCommands {
    Import(ImportKekAction),
    Export(ExportByokAction),
}

impl ByokCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Import(action) => action.run(kms_rest_client).await,
            Self::Export(action) => action.run(kms_rest_client).await,
        }
    }
}
