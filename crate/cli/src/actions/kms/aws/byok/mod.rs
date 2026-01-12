mod export_key_material;
mod import_kek;
pub(crate) mod wrapping_algorithms;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::aws::byok::{export_key_material::ExportByokAction, import_kek::ImportKekAction},
    error::result::KmsCliResult,
};

/// AWS BYOK support.
/// See: <https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html>
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
