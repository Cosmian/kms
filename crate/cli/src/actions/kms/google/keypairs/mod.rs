use clap::Subcommand;
use cosmian_kms_client::KmsClient;
use create::CreateKeyPairsAction;
use disable::DisableKeyPairsAction;
use enable::EnableKeyPairsAction;
use get::GetKeyPairsAction;
use list::ListKeyPairsAction;
use obliterate::ObliterateKeyPairsAction;

use crate::error::result::CosmianResult;

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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        match self {
            Self::Get(action) => action.run(&kms_rest_client.config).await,
            Self::List(action) => action.run(&kms_rest_client.config).await,
            Self::Enable(action) => action.run(&kms_rest_client.config).await,
            Self::Disable(action) => action.run(&kms_rest_client.config).await,
            Self::Obliterate(action) => action.run(&kms_rest_client.config).await,
            Self::Create(action) => Box::pin(action.run(kms_rest_client)).await,
        }
    }
}
