use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// List all RBAC roles.
#[derive(Parser, Debug)]
pub struct ListRolesAction;

impl ListRolesAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .list_roles()
            .await
            .with_context(|| "listing roles")?;

        if response.roles.is_empty() {
            console::Stdout::new("No roles found.").write()?;
        } else {
            let mut output = String::from("Roles:\n");
            for role in &response.roles {
                let builtin_tag = if role.builtin { " [builtin]" } else { "" };
                let desc = role
                    .description
                    .as_deref()
                    .map_or(String::new(), |d| format!(" — {d}"));
                output.push_str(&format!(
                    "  {} ({}){}{}\n",
                    role.name, role.id, builtin_tag, desc
                ));
            }
            console::Stdout::new(&output).write()?;
        }
        Ok(())
    }
}
