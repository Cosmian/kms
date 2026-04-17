use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::error::result::KmsCliResult;

mod create_role;
mod delete_role;
mod get_role;
mod hierarchy;
mod list_roles;
mod permissions;
mod users;

pub use create_role::CreateRoleAction;
pub use delete_role::DeleteRoleAction;
pub use get_role::GetRoleAction;
pub use hierarchy::{AddJuniorAction, HierarchyAction, ListJuniorsAction, RemoveJuniorAction};
pub use list_roles::ListRolesAction;
pub use permissions::{AddPermissionAction, ListPermissionsAction, RemovePermissionAction};
pub use users::{AssignUserAction, ListRoleUsersAction, RevokeUserAction};

/// Manage RBAC roles (NIST Core + Hierarchical RBAC).
///
/// Create, list, update, and delete roles. Manage role permissions,
/// user assignments, and role hierarchy.
#[derive(Subcommand, Debug)]
pub enum RolesAction {
    /// Create a new role
    Create(CreateRoleAction),
    /// List all roles
    List(ListRolesAction),
    /// Get a role by ID
    Get(GetRoleAction),
    /// Delete a role
    Delete(DeleteRoleAction),
    /// Add permissions to a role
    AddPermission(AddPermissionAction),
    /// Remove permissions from a role
    RemovePermission(RemovePermissionAction),
    /// List permissions of a role
    ListPermissions(ListPermissionsAction),
    /// Assign a role to one or more users
    Assign(AssignUserAction),
    /// Revoke a role from a user
    Revoke(RevokeUserAction),
    /// List users assigned to a role
    Members(ListRoleUsersAction),
    /// Add a junior role (role inherits junior's permissions)
    AddJunior(AddJuniorAction),
    /// Remove a junior role from the hierarchy
    RemoveJunior(RemoveJuniorAction),
    /// List direct junior roles
    Juniors(ListJuniorsAction),
    /// Display the role hierarchy tree
    Hierarchy(HierarchyAction),
}

impl RolesAction {
    /// Process the roles action.
    ///
    /// # Errors
    /// Returns an error if the action fails.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Create(action) => action.run(&kms_rest_client).await,
            Self::List(action) => action.run(&kms_rest_client).await,
            Self::Get(action) => action.run(&kms_rest_client).await,
            Self::Delete(action) => action.run(&kms_rest_client).await,
            Self::AddPermission(action) => action.run(&kms_rest_client).await,
            Self::RemovePermission(action) => action.run(&kms_rest_client).await,
            Self::ListPermissions(action) => action.run(&kms_rest_client).await,
            Self::Assign(action) => action.run(&kms_rest_client).await,
            Self::Revoke(action) => action.run(&kms_rest_client).await,
            Self::Members(action) => action.run(&kms_rest_client).await,
            Self::AddJunior(action) => action.run(&kms_rest_client).await,
            Self::RemoveJunior(action) => action.run(&kms_rest_client).await,
            Self::Juniors(action) => action.run(&kms_rest_client).await,
            Self::Hierarchy(action) => action.run(&kms_rest_client).await,
        }
    }
}
