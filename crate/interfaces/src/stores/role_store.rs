use std::collections::HashMap;

use async_trait::async_trait;

use crate::InterfaceResult;

/// Trait that the stores must implement to manage RBAC role assignments.
///
/// Role assignments map users to roles (e.g. "administrator", "operator").
/// Each user can have multiple roles. Roles are used by the RBAC policy engine
/// to evaluate authorization decisions.
#[async_trait(?Send)]
pub trait RoleStore {
    /// Assign a role to a user.
    /// If the assignment already exists, this is a no-op.
    async fn assign_role(&self, user: &str, role: &str) -> InterfaceResult<()>;

    /// Remove a role from a user.
    /// If the assignment does not exist, this is a no-op.
    async fn remove_role(&self, user: &str, role: &str) -> InterfaceResult<()>;

    /// List all roles assigned to a user.
    async fn list_user_roles(&self, user: &str) -> InterfaceResult<Vec<String>>;

    /// List all role assignments in the system.
    /// Returns a map of `user_id` → list of assigned roles.
    async fn list_all_role_assignments(&self) -> InterfaceResult<HashMap<String, Vec<String>>>;
}
