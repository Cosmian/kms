use std::path::PathBuf;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_keypairs::CreateKeypairsAction, disable_keypairs::DisableKeypairsAction,
    enable_keypairs::EnableKeypairsAction, get_keypairs::GetKeypairsAction,
    insert_keypairs::InsertKeypairsAction, list_keypairs::ListKeypairsAction,
    obliterate_keypairs::ObliterateKeypairsAction,
};
use crate::error::result::CliResult;

mod create_keypairs;
mod disable_keypairs;
mod enable_keypairs;
mod get_keypairs;
mod insert_keypairs;
mod list_keypairs;
mod obliterate_keypairs;

pub(crate) const KEYPAIRS_ENDPOINT: &str = "/settings/cse/keypairs/";

/// Insert, get, list, enable, disabled and obliterate keypairs to Gmail API
#[derive(Subcommand)]
pub enum KeypairsCommands {
    Get(GetKeypairsAction),
    List(ListKeypairsAction),
    Insert(InsertKeypairsAction),
    Enable(EnableKeypairsAction),
    Disable(DisableKeypairsAction),
    Obliterate(ObliterateKeypairsAction),
    Create(CreateKeypairsAction),
}

impl KeypairsCommands {
    pub async fn process(&self, conf_path: &PathBuf, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Get(action) => action.run(conf_path).await,
            Self::List(action) => action.run(conf_path).await,
            Self::Insert(action) => action.run(conf_path).await,
            Self::Enable(action) => action.run(conf_path).await,
            Self::Disable(action) => action.run(conf_path).await,
            Self::Obliterate(action) => action.run(conf_path).await,
            Self::Create(action) => action.run(conf_path, kms_rest_client).await,
        }
    }
}
