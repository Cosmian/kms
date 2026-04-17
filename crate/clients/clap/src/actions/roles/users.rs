use clap::Parser;
use cosmian_kms_client::{KmsClient, reexport::cosmian_kms_access::rbac::AssignRoleRequest};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Assign an RBAC role to one or more users.
#[derive(Parser, Debug)]
pub struct AssignUserAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,

    /// The user identifiers to assign
    #[clap(long, short = 'u', required = true, num_args = 1..)]
    pub users: Vec<String>,
}

impl AssignUserAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .assign_role_to_users(
                &self.role_id,
                &AssignRoleRequest {
                    user_ids: self.users.clone(),
                },
            )
            .await
            .with_context(|| format!("assigning role '{}' to users", self.role_id))?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// Revoke an RBAC role from a user.
#[derive(Parser, Debug)]
pub struct RevokeUserAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,

    /// The user identifier to revoke from
    #[clap(long, short = 'u', required = true)]
    pub user: String,
}

impl RevokeUserAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .revoke_role_from_user(&self.role_id, &self.user)
            .await
            .with_context(|| {
                format!("revoking role '{}' from user '{}'", self.role_id, self.user)
            })?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// List users assigned to an RBAC role.
#[derive(Parser, Debug)]
pub struct ListRoleUsersAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,
}

impl ListRoleUsersAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .list_role_users(&self.role_id)
            .await
            .with_context(|| format!("listing users for role '{}'", self.role_id))?;

        if response.users.is_empty() {
            console::Stdout::new(&format!("Role '{}' has no assigned users.", self.role_id))
                .write()?;
        } else {
            let mut output = format!("Users assigned to role '{}':\n", self.role_id);
            for ur in &response.users {
                output.push_str(&format!(
                    "  {} (granted by: {})\n",
                    ur.user_id, ur.granted_by
                ));
            }
            console::Stdout::new(&output).write()?;
        }
        Ok(())
    }
}
