use std::fmt::Write as _;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use super::console;
use crate::error::result::{KmsCliResult, KmsCliResultHelper};

/// Manage RBAC (Role-Based Access Control) role assignments.
///
/// Only privileged users (administrators) can manage roles.
/// Available built-in roles: administrator, operator, auditor, readonly.
/// Custom roles may be defined in the Rego policy.
#[derive(Parser, Debug)]
pub enum RbacAction {
    /// Assign a role to a user
    Assign(AssignRole),
    /// Remove a role from a user
    Remove(RemoveRole),
    /// List roles assigned to a specific user
    #[command(name = "list")]
    ListUser(ListUserRoles),
    /// List all role assignments across all users
    #[command(name = "list-all")]
    ListAll(ListAllRoles),
    /// Show RBAC enforcement status on the server
    Status(RbacStatusAction),
}

impl RbacAction {
    /// Processes the RBAC action.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Assign(action) => action.run(kms_rest_client).await?,
            Self::Remove(action) => action.run(kms_rest_client).await?,
            Self::ListUser(action) => action.run(kms_rest_client).await?,
            Self::ListAll(action) => action.run(kms_rest_client).await?,
            Self::Status(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}

/// Assign a role to a user.
///
/// Example:
///   ckms rbac assign alice@example.com operator
#[derive(Parser, Debug)]
pub struct AssignRole {
    /// The user identifier to assign the role to
    #[clap(required = true)]
    pub user_id: String,

    /// The role name to assign (e.g. administrator, operator, auditor, readonly)
    #[clap(required = true)]
    pub role: String,
}

impl AssignRole {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        kms_rest_client
            .rbac_assign_role(&self.user_id, &self.role)
            .await
            .with_context(|| "Failed to assign RBAC role")?;

        console::Stdout::new(&format!(
            "Role '{}' successfully assigned to user '{}'",
            self.role, self.user_id
        ))
        .write()?;

        Ok(())
    }
}

/// Remove a role from a user.
///
/// Example:
///   ckms rbac remove alice@example.com operator
#[derive(Parser, Debug)]
pub struct RemoveRole {
    /// The user identifier to remove the role from
    #[clap(required = true)]
    pub user_id: String,

    /// The role name to remove
    #[clap(required = true)]
    pub role: String,
}

impl RemoveRole {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        kms_rest_client
            .rbac_remove_role(&self.user_id, &self.role)
            .await
            .with_context(|| "Failed to remove RBAC role")?;

        console::Stdout::new(&format!(
            "Role '{}' successfully removed from user '{}'",
            self.role, self.user_id
        ))
        .write()?;

        Ok(())
    }
}

/// List the roles assigned to a specific user.
///
/// Example:
///   ckms rbac list alice@example.com
#[derive(Parser, Debug)]
pub struct ListUserRoles {
    /// The user identifier to list roles for
    #[clap(required = true)]
    pub user_id: String,
}

impl ListUserRoles {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let roles = kms_rest_client
            .rbac_list_user_roles(&self.user_id)
            .await
            .with_context(|| "Failed to list user roles")?;

        if roles.is_empty() {
            console::Stdout::new(&format!("No roles assigned to user '{}'", self.user_id))
                .write()?;
        } else {
            let mut output = format!("Roles assigned to user '{}':\n", self.user_id);
            for role in &roles {
                let _ = writeln!(output, "  - {role}");
            }
            console::Stdout::new(&output).write()?;
        }

        Ok(())
    }
}

/// List all role assignments across all users.
///
/// Example:
///   ckms rbac list-all
#[derive(Parser, Debug)]
pub struct ListAllRoles;

impl ListAllRoles {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let assignments = kms_rest_client
            .rbac_list_all_roles()
            .await
            .with_context(|| "Failed to list all role assignments")?;

        if assignments.is_empty() {
            console::Stdout::new("No role assignments found.").write()?;
        } else {
            let mut output = String::from("Role assignments:\n");
            for entry in &assignments {
                let user_id = entry.get("user_id").and_then(|v| v.as_str()).unwrap_or("?");
                let role = entry.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                let _ = writeln!(output, "  {user_id} -> {role}");
            }
            console::Stdout::new(&output).write()?;
        }

        Ok(())
    }
}

/// Show whether RBAC enforcement is enabled on the server.
///
/// Example:
///   ckms rbac status
#[derive(Parser, Debug)]
pub struct RbacStatusAction;

impl RbacStatusAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let status = kms_rest_client
            .rbac_status()
            .await
            .with_context(|| "Failed to get RBAC status")?;

        let enabled = status
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let engine = status
            .get("engine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let output = if enabled {
            format!("RBAC enforcement is ENABLED (engine: {engine})")
        } else {
            "RBAC enforcement is DISABLED".to_owned()
        };
        console::Stdout::new(&output).write()?;

        Ok(())
    }
}
