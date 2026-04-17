use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Get an RBAC role by its ID.
#[derive(Parser, Debug)]
pub struct GetRoleAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,
}

impl GetRoleAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .get_role(&self.role_id)
            .await
            .with_context(|| format!("getting role '{}'", self.role_id))?;

        let role = &response.role;
        let builtin_tag = if role.builtin { " [builtin]" } else { "" };
        let desc = role.description.as_deref().unwrap_or("(no description)");
        console::Stdout::new(&format!(
            "Role: {} ({}){}\nDescription: {}",
            role.name, role.id, builtin_tag, desc
        ))
        .write()?;
        Ok(())
    }
}
