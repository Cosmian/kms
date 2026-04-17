use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::KmipOperation;

use crate::InterfaceResult;

/// Re-export role types from the access crate for convenience.
pub use cosmian_kms_access::rbac::{Role, RoleHierarchyEdge, RoleTreeNode, UserRole};

/// Trait that stores must implement to support NIST Core RBAC.
///
/// This is separate from `PermissionsStore` (which handles legacy per-user
/// direct grants) so that backends can adopt RBAC incrementally.
#[async_trait(?Send)]
pub trait RoleStore {
    // ── Role CRUD ───────────────────────────────────────────────────────

    /// Create a new role. Returns an error if a role with the same `id` already exists.
    async fn create_role(&self, role: &Role) -> InterfaceResult<()>;

    /// Retrieve a role by its `id`. Returns an error if not found.
    async fn get_role(&self, role_id: &str) -> InterfaceResult<Role>;

    /// List all roles (built-in and custom).
    async fn list_roles(&self) -> InterfaceResult<Vec<Role>>;

    /// Update a role's mutable fields (name, description).
    /// Built-in roles may only have their description updated.
    async fn update_role(&self, role: &Role) -> InterfaceResult<()>;

    /// Delete a role and cascade-remove its PA and UA entries.
    /// Built-in roles cannot be deleted.
    async fn delete_role(&self, role_id: &str) -> InterfaceResult<()>;

    // ── Permission–Role assignment (PA) ─────────────────────────────────

    /// Grant `operations` on `object_id` to `role_id`.
    /// If the role already has some operations on the object, the sets are merged.
    async fn assign_permissions_to_role(
        &self,
        role_id: &str,
        object_id: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()>;

    /// Remove `operations` on `object_id` from `role_id`.
    /// If the resulting set is empty, the PA row is removed.
    async fn remove_permissions_from_role(
        &self,
        role_id: &str,
        object_id: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()>;

    /// List all permissions assigned to a role.
    /// Returns a map: `object_id → set of operations`.
    async fn list_role_permissions(
        &self,
        role_id: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>>;

    // ── User–Role assignment (UA) ───────────────────────────────────────

    /// Assign a role to a user. `granted_by` records who made the assignment.
    async fn assign_role_to_user(
        &self,
        user_id: &str,
        role_id: &str,
        granted_by: &str,
    ) -> InterfaceResult<()>;

    /// Revoke a role from a user.
    async fn revoke_role_from_user(&self, user_id: &str, role_id: &str) -> InterfaceResult<()>;

    /// List all roles assigned to a user.
    async fn list_user_roles(&self, user_id: &str) -> InterfaceResult<Vec<Role>>;

    /// List all users assigned to a role.
    async fn list_role_users(&self, role_id: &str) -> InterfaceResult<Vec<UserRole>>;

    // ── Effective permissions ────────────────────────────────────────────

    /// Compute the set of KMIP operations a user can perform on an object,
    /// considering all roles assigned to that user (including inherited roles
    /// from the role hierarchy).
    ///
    /// This does **not** include direct (legacy) grants — the caller must
    /// union those from `PermissionsStore::list_user_operations_on_object`.
    async fn role_based_operations_on_object(
        &self,
        uid: &str,
        user: &str,
    ) -> InterfaceResult<HashSet<KmipOperation>>;

    // ── Hierarchical RBAC ───────────────────────────────────────────────

    /// Add a hierarchy edge: `senior_role_id` inherits all permissions of
    /// `junior_role_id`. Rejects self-loops and cycles.
    async fn add_hierarchy_edge(
        &self,
        senior_role_id: &str,
        junior_role_id: &str,
    ) -> InterfaceResult<()>;

    /// Remove a hierarchy edge.
    async fn remove_hierarchy_edge(
        &self,
        senior_role_id: &str,
        junior_role_id: &str,
    ) -> InterfaceResult<()>;

    /// List the direct junior roles of `role_id`.
    async fn list_junior_roles(&self, role_id: &str) -> InterfaceResult<Vec<Role>>;

    /// List the direct senior roles of `role_id`.
    async fn list_senior_roles(&self, role_id: &str) -> InterfaceResult<Vec<Role>>;

    /// Return all hierarchy edges in the system.
    async fn list_all_hierarchy_edges(&self) -> InterfaceResult<Vec<RoleHierarchyEdge>>;

    /// Build a tree of roles rooted at `role_id`, recursively including all juniors.
    async fn get_role_hierarchy_tree(&self, role_id: &str) -> InterfaceResult<RoleTreeNode>;
}
