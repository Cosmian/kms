mod export_byok;
mod import_kek;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub(crate) use export_byok::ExportByokAction;
pub(crate) use import_kek::ImportKekAction;

use crate::error::result::KmsCliResult;

/// Azure BYOK support.
/// See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>
#[derive(Subcommand)]
pub enum ByokCommands {
    Import(ImportKekAction),
    Export(ExportByokAction),
}

impl ByokCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Import(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Export(action) => action.run(kms_rest_client).await,
        }
    }
}
