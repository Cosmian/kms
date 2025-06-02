use clap::Subcommand;
use cosmian_kms_client::KmsClientConfig;

use self::{
    delete_identities::DeleteIdentitiesAction, get_identities::GetIdentitiesAction,
    insert_identities::InsertIdentitiesAction, list_identities::ListIdentitiesAction,
    patch_identities::PatchIdentitiesAction,
};
use crate::error::result::KmsCliResult;

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
    pub async fn process(&self, config: KmsClientConfig) -> KmsCliResult<()> {
        match self {
            Self::Get(action) => action.run(config).await,
            Self::List(action) => action.run(config).await,
            Self::Insert(action) => action.run(config).await,
            Self::Delete(action) => action.run(config).await,
            Self::Patch(action) => action.run(config).await,
        }
    }
}
