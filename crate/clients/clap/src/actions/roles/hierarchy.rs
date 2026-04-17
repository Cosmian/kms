use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Add a junior role to a senior role (role inheritance).
///
/// The senior role will inherit all permissions of the junior role.
#[derive(Parser, Debug)]
pub struct AddJuniorAction {
    /// The senior role ID (will inherit permissions)
    #[clap(required = true)]
    pub role_id: String,

    /// The junior role ID (whose permissions will be inherited)
    #[clap(long, required = true)]
    pub junior: String,
}

impl AddJuniorAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .add_junior_role(&self.role_id, &self.junior)
            .await
            .with_context(|| {
                format!("adding junior '{}' to role '{}'", self.junior, self.role_id)
            })?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// Remove a junior role from a senior role.
#[derive(Parser, Debug)]
pub struct RemoveJuniorAction {
    /// The senior role ID
    #[clap(required = true)]
    pub role_id: String,

    /// The junior role ID to remove
    #[clap(long, required = true)]
    pub junior: String,
}

impl RemoveJuniorAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .remove_junior_role(&self.role_id, &self.junior)
            .await
            .with_context(|| {
                format!(
                    "removing junior '{}' from role '{}'",
                    self.junior, self.role_id
                )
            })?;

        console::Stdout::new(&response.success).write()?;
        Ok(())
    }
}

/// List the direct junior roles of a role.
#[derive(Parser, Debug)]
pub struct ListJuniorsAction {
    /// The role identifier
    #[clap(required = true)]
    pub role_id: String,
}

impl ListJuniorsAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .list_junior_roles(&self.role_id)
            .await
            .with_context(|| format!("listing juniors of role '{}'", self.role_id))?;

        if response.roles.is_empty() {
            console::Stdout::new(&format!("Role '{}' has no junior roles.", self.role_id))
                .write()?;
        } else {
            let mut out = format!("Junior roles of '{}':\n", self.role_id);
            for role in &response.roles {
                let builtin_tag = if role.builtin { " [builtin]" } else { "" };
                out.push_str(&format!("  - {} ({}){}\n", role.name, role.id, builtin_tag));
            }
            console::Stdout::new(&out).write()?;
        }
        Ok(())
    }
}

/// Display the full role hierarchy tree starting from a given role.
#[derive(Parser, Debug)]
pub struct HierarchyAction {
    /// The root role ID (defaults to showing the full hierarchy)
    #[clap(required = true)]
    pub role_id: String,
}

impl HierarchyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response = kms_rest_client
            .get_role_hierarchy_tree(&self.role_id)
            .await
            .with_context(|| format!("getting hierarchy for role '{}'", self.role_id))?;

        let mut out = String::new();
        format_tree_node(&response.tree, "", true, &mut out);
        console::Stdout::new(&out).write()?;
        Ok(())
    }
}

fn format_tree_node(
    node: &cosmian_kms_client::reexport::cosmian_kms_access::rbac::RoleTreeNode,
    prefix: &str,
    is_last: bool,
    out: &mut String,
) {
    let connector = if prefix.is_empty() {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let builtin_tag = if node.role.builtin { " [builtin]" } else { "" };
    out.push_str(&format!(
        "{prefix}{connector}{} ({}){}\n",
        node.role.name, node.role.id, builtin_tag
    ));
    let child_prefix = if prefix.is_empty() {
        String::new()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };
    for (i, junior) in node.juniors.iter().enumerate() {
        let last = i == node.juniors.len() - 1;
        format_tree_node(junior, &child_prefix, last, out);
    }
}
