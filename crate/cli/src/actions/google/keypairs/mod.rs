use std::path::PathBuf;

use clap::Subcommand;
// use cosmian_kms_client::KmsClient;

// use self::{get_keypairs::GetKeypairsAction, insert_keypairs::InsertKeypairsAction};

use crate::{
    error::CliError
};

// mod get_keypairs;
// mod insert_keypairs;


// Create, destroy, import, and export symmetric keys
#[derive(Subcommand)]
pub enum KeypairsCommands {
    // Get(GetKeypairsAction),
    // Insert(InsertKeypairsAction),
}

impl KeypairsCommands {
    pub async fn process(&self, _conf_path: &PathBuf) -> Result<(), CliError> {
        // match self {
        //     Self::Get(action) => action.run(conf_path).await?,
        //     Self::Insert(action) => action.run().await?,
        // };

        Ok(())
    }
}
