use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Delete an RBAC role.
///
/// Built-in roles cannot be deleted. Deleting a role also removes all
/// associated permissions and user assignments.
#[derive(Parser, Debug)]
pub struct DeleteRoleAction {
    /// The role identifier to delete
    #[clap(required = true)]
    pub role_id: String,
}

impl DeleteRoleAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .delete_role(&self.role_id)
            .await
            .with_context(|| format!("deleting role '{}'", self.role_id))?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}
