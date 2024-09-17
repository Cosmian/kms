use std::path::PathBuf;

use clap::Subcommand;

use self::{
    delete_identities::DeleteIdentitiesAction, get_identities::GetIdentitiesAction,
    insert_identities::InsertIdentitiesAction, list_identities::ListIdentitiesAction,
    patch_identities::PatchIdentitiesAction,
};
use crate::error::result::CliResult;

mod delete_identities;
mod get_identities;
mod insert_identities;
mod list_identities;
mod patch_identities;

pub(crate) const IDENTITIES_ENDPOINT: &str = "/settings/cse/identities/";

/// Insert, get, list, patch and delete identities from Gmail API.
#[derive(Subcommand)]
pub enum IdentitiesCommands {
    Get(GetIdentitiesAction),
    List(ListIdentitiesAction),
    Insert(InsertIdentitiesAction),
    Delete(DeleteIdentitiesAction),
    Patch(PatchIdentitiesAction),
}

impl IdentitiesCommands {
    pub async fn process(&self, conf_path: &PathBuf) -> CliResult<()> {
        match self {
            Self::Get(action) => action.run(conf_path).await,
            Self::List(action) => action.run(conf_path).await,
            Self::Insert(action) => action.run(conf_path).await,
            Self::Delete(action) => action.run(conf_path).await,
            Self::Patch(action) => action.run(conf_path).await,
        }
    }
}
