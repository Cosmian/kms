use std::path::PathBuf;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
use create::CreateKeyPairsAction;
use disable::DisableKeyPairsAction;
use enable::EnableKeyPairsAction;
use get::GetKeyPairsAction;
use list::ListKeyPairsAction;
use obliterate::ObliterateKeyPairsAction;

use crate::error::result::CliResult;

mod create;
mod disable;
mod enable;
mod get;
mod list;
mod obliterate;

pub(crate) const KEY_PAIRS_ENDPOINT: &str = "/settings/cse/keypairs/";

/// Insert, get, list, enable, disabled and obliterate key pairs to Gmail API
#[derive(Subcommand)]
pub enum KeyPairsCommands {
    Get(GetKeyPairsAction),
    List(ListKeyPairsAction),
    Enable(EnableKeyPairsAction),
    Disable(DisableKeyPairsAction),
    Obliterate(ObliterateKeyPairsAction),
    Create(CreateKeyPairsAction),
}

impl KeyPairsCommands {
    pub async fn process(&self, conf_path: &PathBuf, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Get(action) => action.run(conf_path).await,
            Self::List(action) => action.run(conf_path).await,
            Self::Enable(action) => action.run(conf_path).await,
            Self::Disable(action) => action.run(conf_path).await,
            Self::Obliterate(action) => action.run(conf_path).await,
            Self::Create(action) => action.run(conf_path, kms_rest_client).await,
        }
    }
}
