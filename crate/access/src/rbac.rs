use std::collections::{HashMap, HashSet};

use cosmian_kmip::kmip_2_1::KmipOperation;
use serde::{Deserialize, Serialize};

/// A named bundle of permissions that can be assigned to users.
///
/// Implements NIST Core RBAC (INCITS 359-2012) role concept.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    /// Unique identifier (slug, e.g. "key-operator")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Optional description of this role's purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this role is built-in (cannot be deleted)
    #[serde(default)]
    pub builtin: bool,
}

/// A permission assigned to a role: the role can perform `operations` on `object_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolePermission {
    /// Role identifier
    pub role_id: String,
    /// Object UID or `"*"` for wildcard (all objects)
    pub object_id: String,
    /// Granted KMIP operations
    pub operations: HashSet<KmipOperation>,
}

/// A user–role assignment (UA).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRole {
    /// The user receiving the role
    pub user_id: String,
    /// The assigned role
    pub role_id: String,
    /// Who granted this assignment
    pub granted_by: String,
}

/// Summary of a user's effective permissions on a single object,
/// showing contributions from direct grants and role-based grants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePermission {
    pub object_id: String,
    /// Operations granted directly (via `read_access` / legacy grants)
    pub direct_operations: HashSet<KmipOperation>,
    /// Operations granted via roles: role_id → operations
    pub role_operations: HashMap<String, HashSet<KmipOperation>>,
}

impl EffectivePermission {
    /// Returns the union of all operations from all sources.
    #[must_use]
    pub fn all_operations(&self) -> HashSet<KmipOperation> {
        let mut ops = self.direct_operations.clone();
        for role_ops in self.role_operations.values() {
            ops.extend(role_ops);
        }
        ops
    }
}

// ── Hierarchical RBAC types ─────────────────────────────────────────────

/// An edge in the role hierarchy DAG: `senior_role_id` inherits all
/// permissions of `junior_role_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleHierarchyEdge {
    pub senior_role_id: String,
    pub junior_role_id: String,
}

/// A tree node used to visualize the role hierarchy from a given root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleTreeNode {
    pub role: Role,
    pub juniors: Vec<RoleTreeNode>,
}

// ── REST API DTO types (shared between server routes and CLI client) ────

/// Request body for `POST /roles`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request body for `PUT /roles/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Request body for `POST /roles/{id}/permissions` and `DELETE /roles/{id}/permissions`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissionsRequest {
    pub object_id: String,
    pub operations: HashSet<KmipOperation>,
}

/// Request body for `POST /roles/{id}/users`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub user_ids: Vec<String>,
}

/// Response for single-role endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleResponse {
    pub role: Role,
}

/// Response for `GET /roles`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolesListResponse {
    pub roles: Vec<Role>,
}

/// Response for `GET /roles/{id}/users`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleUsersResponse {
    pub users: Vec<UserRole>,
}

/// A permission entry for a specific object in a role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissionEntry {
    pub object_id: String,
    pub operations: HashSet<KmipOperation>,
}

/// Response for `GET /roles/{id}/permissions`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissionsResponse {
    pub permissions: Vec<RolePermissionEntry>,
}

/// Response for `GET /users/{user_id}/effective-permissions`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePermissionsResponse {
    pub operations: HashSet<KmipOperation>,
}

/// Request body for `POST /roles/{id}/juniors/{junior_id}` (no body needed, but kept for consistency)
/// The senior and junior IDs come from the URL path.

/// Response for `GET /roles/{id}/juniors` or `GET /roles/{id}/seniors`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleHierarchyListResponse {
    pub roles: Vec<Role>,
}

/// Response for `GET /roles/{id}/hierarchy` — returns the full subtree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleHierarchyTreeResponse {
    pub tree: RoleTreeNode,
}

/// Response for `GET /roles/hierarchy` — returns all hierarchy edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleHierarchyEdgesResponse {
    pub edges: Vec<RoleHierarchyEdge>,
}

/// RBAC enforcement mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RbacEnforcementMode {
    /// Effective permissions = owner ∪ direct_grants ∪ role_grants.
    /// RBAC never restricts access that would otherwise be available through direct grants.
    #[default]
    Additive,
    /// Effective permissions = (direct_grants ∪ role_grants) ∩ role_ceiling.
    /// Roles define the maximum permission set; direct grants cannot exceed what the
    /// user's roles allow. Owners always have full access regardless of mode.
    Restrictive,
}

/// Configuration for the RBAC subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RbacConfig {
    /// When `true`, role-based access control is active.
    /// When `false` (default), the system uses legacy per-user grants only.
    #[serde(default)]
    pub enabled: bool,
    /// Users to auto-assign the built-in `admin` role on first startup.
    #[serde(default)]
    pub bootstrap_admins: Vec<String>,
    /// When `true`, the `Get` operation only grants the `Get` operation itself.
    /// When `false` (default), `Get` implies all non-lifecycle operations (backward compatible).
    #[serde(default)]
    pub strict_get_privilege: bool,
    /// Controls how RBAC permissions interact with direct grants.
    #[serde(default)]
    pub enforcement_mode: RbacEnforcementMode,
    /// When `true`, only users with admin/operator roles (or object owners) can call
    /// grant_access / revoke_access. When `false` (default), only ownership is checked.
    #[serde(default)]
    pub restrict_grant_to_roles: bool,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bootstrap_admins: Vec::new(),
            strict_get_privilege: false,
            enforcement_mode: RbacEnforcementMode::default(),
            restrict_grant_to_roles: false,
        }
    }
}

/// Well-known built-in role identifiers.
pub mod builtin_roles {
    /// Full administrative access — role/user management + all operations.
    pub const ADMIN: &str = "admin";
    /// Day-to-day key lifecycle: create, import, certify, rekey, destroy, revoke.
    pub const OPERATOR: &str = "operator";
    /// Use keys for cryptographic operations but cannot manage them.
    pub const CRYPTO_USER: &str = "crypto-user";
    /// Read-only inspection: get, get-attributes, locate.
    pub const AUDITOR: &str = "auditor";
    /// Key escrow and backup: export, import, get.
    pub const KEY_CUSTODIAN: &str = "key-custodian";

    /// Returns all built-in role IDs.
    #[must_use]
    pub fn all() -> &'static [&'static str] {
        &[ADMIN, OPERATOR, CRYPTO_USER, AUDITOR, KEY_CUSTODIAN]
    }
}

/// Builds the set of default permissions for a built-in role on the wildcard object `"*"`.
#[must_use]
pub fn builtin_role_permissions(role_id: &str) -> HashSet<KmipOperation> {
    use cosmian_kmip::kmip_2_1::KmipOperation::{
        Certify, Create, Decrypt, DeriveKey, Destroy, Encrypt, Export, Get, GetAttributes, Hash,
        Import, Locate, MAC, Rekey, Revoke, Sign, SignatureVerify, Validate,
    };
    match role_id {
        builtin_roles::ADMIN => {
            // All operations
            HashSet::from([
                Create,
                Certify,
                Decrypt,
                DeriveKey,
                Destroy,
                Encrypt,
                Export,
                Get,
                GetAttributes,
                Hash,
                Import,
                Locate,
                MAC,
                Revoke,
                Rekey,
                Sign,
                SignatureVerify,
                Validate,
            ])
        }
        builtin_roles::OPERATOR => HashSet::from([
            Create,
            Import,
            Certify,
            Rekey,
            Destroy,
            Revoke,
            Locate,
            GetAttributes,
        ]),
        builtin_roles::CRYPTO_USER => HashSet::from([
            Encrypt,
            Decrypt,
            Sign,
            SignatureVerify,
            MAC,
            Hash,
            DeriveKey,
            Locate,
            GetAttributes,
        ]),
        builtin_roles::AUDITOR => HashSet::from([Get, GetAttributes, Locate]),
        builtin_roles::KEY_CUSTODIAN => HashSet::from([Export, Import, Get, GetAttributes, Locate]),
        _ => HashSet::new(),
    }
}

/// Builds the `Role` struct for a built-in role.
#[must_use]
pub fn builtin_role(role_id: &str) -> Option<Role> {
    let (name, description) = match role_id {
        builtin_roles::ADMIN => (
            "Administrator",
            "Full administrative access — role/user management and all KMIP operations",
        ),
        builtin_roles::OPERATOR => (
            "Operator",
            "Day-to-day key lifecycle: create, import, certify, rekey, destroy, revoke",
        ),
        builtin_roles::CRYPTO_USER => (
            "Crypto User",
            "Use keys for cryptographic operations (encrypt, decrypt, sign, verify, MAC, hash)",
        ),
        builtin_roles::AUDITOR => (
            "Auditor",
            "Read-only inspection: get, get-attributes, locate",
        ),
        builtin_roles::KEY_CUSTODIAN => (
            "Key Custodian",
            "Key escrow and backup: export, import, get",
        ),
        _ => return None,
    };
    Some(Role {
        id: role_id.to_owned(),
        name: name.to_owned(),
        description: Some(description.to_owned()),
        builtin: true,
    })
}

/// Returns the default hierarchy edges for built-in roles.
///
/// ```text
/// admin
///   ├── operator
///   │     └── crypto-user
///   └── key-custodian
/// auditor (standalone)
/// ```
#[must_use]
pub fn builtin_hierarchy_edges() -> Vec<RoleHierarchyEdge> {
    vec![
        RoleHierarchyEdge {
            senior_role_id: builtin_roles::ADMIN.to_owned(),
            junior_role_id: builtin_roles::OPERATOR.to_owned(),
        },
        RoleHierarchyEdge {
            senior_role_id: builtin_roles::ADMIN.to_owned(),
            junior_role_id: builtin_roles::KEY_CUSTODIAN.to_owned(),
        },
        RoleHierarchyEdge {
            senior_role_id: builtin_roles::OPERATOR.to_owned(),
            junior_role_id: builtin_roles::CRYPTO_USER.to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_roles_have_permissions() {
        for role_id in builtin_roles::all() {
            let perms = builtin_role_permissions(role_id);
            assert!(
                !perms.is_empty(),
                "built-in role {role_id} should have permissions"
            );
        }
    }

    #[test]
    fn builtin_roles_have_metadata() {
        for role_id in builtin_roles::all() {
            let role = builtin_role(role_id);
            assert!(
                role.is_some(),
                "built-in role {role_id} should have metadata"
            );
            let role = role.unwrap();
            assert!(role.builtin);
            assert_eq!(role.id, *role_id);
        }
    }

    #[test]
    fn unknown_role_returns_empty_permissions() {
        assert!(builtin_role_permissions("unknown-role").is_empty());
    }

    #[test]
    fn unknown_role_returns_none() {
        assert!(builtin_role("unknown-role").is_none());
    }

    #[test]
    fn effective_permission_union() {
        use cosmian_kmip::kmip_2_1::KmipOperation::{Decrypt, Encrypt, Sign};
        let ep = EffectivePermission {
            object_id: "obj-1".to_owned(),
            direct_operations: HashSet::from([Encrypt]),
            role_operations: HashMap::from([
                ("crypto-user".to_owned(), HashSet::from([Decrypt])),
                ("signer".to_owned(), HashSet::from([Sign])),
            ]),
        };
        let all = ep.all_operations();
        assert!(all.contains(&Encrypt));
        assert!(all.contains(&Decrypt));
        assert!(all.contains(&Sign));
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn builtin_hierarchy_has_expected_edges() {
        let edges = builtin_hierarchy_edges();
        assert_eq!(edges.len(), 3);
        // admin → operator
        assert!(edges.iter().any(|e| e.senior_role_id == "admin" && e.junior_role_id == "operator"));
        // admin → key-custodian
        assert!(edges.iter().any(|e| e.senior_role_id == "admin" && e.junior_role_id == "key-custodian"));
        // operator → crypto-user
        assert!(edges.iter().any(|e| e.senior_role_id == "operator" && e.junior_role_id == "crypto-user"));
    }
}
