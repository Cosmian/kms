use std::collections::HashMap;

use super::Database;
use crate::error::DbResult;

/// Methods that manipulate RBAC role assignments
impl Database {
    /// Assign a role to a user.
    pub async fn assign_role(&self, user: &str, role: &str) -> DbResult<()> {
        Ok(self.roles.assign_role(user, role).await?)
    }

    /// Remove a role from a user.
    pub async fn remove_role(&self, user: &str, role: &str) -> DbResult<()> {
        Ok(self.roles.remove_role(user, role).await?)
    }

    /// List all roles assigned to a user.
    pub async fn list_user_roles(&self, user: &str) -> DbResult<Vec<String>> {
        Ok(self.roles.list_user_roles(user).await?)
    }

    /// List all role assignments in the system.
    pub async fn list_all_role_assignments(&self) -> DbResult<HashMap<String, Vec<String>>> {
        Ok(self.roles.list_all_role_assignments().await?)
    }
}
