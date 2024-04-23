use std::path::PathBuf;

use clap::Subcommand;

use self::{get_keypairs::GetKeypairsAction, list_keypairs::ListKeypairsAction, insert_keypairs::InsertKeypairsAction, enable_keypairs::EnableKeypairsAction, disable_keypairs::DisableKeypairsAction, obliterate_keypairs::ObliterateKeypairsAction};

use crate::{
    error::CliError,
};

mod get_keypairs;
mod list_keypairs;
mod insert_keypairs;
mod enable_keypairs;
mod disable_keypairs;
mod obliterate_keypairs;

/// Insert, get, list, enable, disabled and obliterate keypairs to Gmail API
#[derive(Subcommand)]
pub enum KeypairsCommands {
    Get(GetKeypairsAction),
    List(ListKeypairsAction),
    Insert(InsertKeypairsAction),
    Enable(EnableKeypairsAction),
    Disable(DisableKeypairsAction),
    Obliterate(ObliterateKeypairsAction),
}

impl KeypairsCommands {
    pub async fn process(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        match self {
            Self::Get(action) => action.run(conf_path).await?,
            Self::List(action) => action.run(conf_path).await?,
            Self::Insert(action) => action.run(conf_path).await?,
            Self::Enable(action) => action.run(conf_path).await?,
            Self::Disable(action) => action.run(conf_path).await?,
            Self::Obliterate(action) => action.run(conf_path).await?,
        };

        Ok(())
    }
}
