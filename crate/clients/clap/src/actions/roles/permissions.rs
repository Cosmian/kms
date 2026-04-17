use clap::Parser;
use cosmian_kms_client::{
    KmsClient, kmip_2_1::KmipOperation, reexport::cosmian_kms_access::rbac::RolePermissionsRequest,
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Add permissions to an RBAC role.
///
/// Grants the role the ability to perform the specified KMIP operations on
/// the given object (or `*` for all objects).
///
/// Multiple operations must be supplied whitespace-separated, e.g.:
/// `ckms roles add-permission my-role --operations encrypt decrypt --object-id '*'`
#[derive(Parser, Debug)]
pub struct AddPermissionAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,

    /// The KMIP operations to grant
    #[clap(long, required = true, num_args = 1..)]
    pub operations: Vec<KmipOperation>,

    /// The object UID to grant on, or `*` for all objects
    #[clap(long, short = 'o', default_value = "*")]
    pub object_id: String,
}

impl AddPermissionAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .add_role_permissions(
                &self.role_id,
                &RolePermissionsRequest {
                    object_id: self.object_id.clone(),
                    operations: self.operations.iter().copied().collect(),
                },
            )
            .await
            .with_context(|| format!("adding permissions to role '{}'", self.role_id))?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// Remove permissions from an RBAC role.
///
/// Revokes the specified KMIP operations on the given object from the role.
#[derive(Parser, Debug)]
pub struct RemovePermissionAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,

    /// The KMIP operations to revoke
    #[clap(long, required = true, num_args = 1..)]
    pub operations: Vec<KmipOperation>,

    /// The object UID to revoke from, or `*` for all objects
    #[clap(long, short = 'o', default_value = "*")]
    pub object_id: String,
}

impl RemovePermissionAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .remove_role_permissions(
                &self.role_id,
                &RolePermissionsRequest {
                    object_id: self.object_id.clone(),
                    operations: self.operations.iter().copied().collect(),
                },
            )
            .await
            .with_context(|| format!("removing permissions from role '{}'", self.role_id))?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// List permissions of an RBAC role.
#[derive(Parser, Debug)]
pub struct ListPermissionsAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,
}

impl ListPermissionsAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .list_role_permissions(&self.role_id)
            .await
            .with_context(|| format!("listing permissions for role '{}'", self.role_id))?;

        if response.permissions.is_empty() {
            console::Stdout::new(&format!("Role '{}' has no permissions.", self.role_id))
                .write()?;
        } else {
            let mut output = format!("Permissions for role '{}':\n", self.role_id);
            for entry in &response.permissions {
                let ops: Vec<String> = entry.operations.iter().map(ToString::to_string).collect();
                output.push_str(&format!(
                    "  object: {} → [{}]\n",
                    entry.object_id,
                    ops.join(", ")
                ));
            }
            console::Stdout::new(&output).write()?;
        }
        Ok(())
    }
}
