use clap::Parser;
use cosmian_kms_client::{KmsClient, reexport::cosmian_kms_access::rbac::CreateRoleRequest};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create a new RBAC role.
///
/// A role is a named bundle of permissions that can be assigned to users.
/// Use `add-permission` to grant KMIP operations to the role, and `assign` to
/// assign the role to users.
#[derive(Parser, Debug)]
pub struct CreateRoleAction {
    /// The role identifier (slug, e.g. "key-operator")
    #[clap(required = true)]
    pub id: String,

    /// Human-readable name for the role
    #[clap(long, short = 'n', required = true)]
    pub name: String,

    /// Optional description of this role's purpose
    #[clap(long, short = 'd')]
    pub description: Option<String>,
}

impl CreateRoleAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .create_role(&CreateRoleRequest {
                id: self.id.clone(),
                name: self.name.clone(),
                description: self.description.clone(),
            })
            .await
            .with_context(|| "creating role")?;

        let role = &response.role;
        console::Stdout::new(&format!("Role created: {} ({})", role.name, role.id)).write()?;
        Ok(())
    }
}
