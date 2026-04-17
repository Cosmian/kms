use std::collections::{HashMap, HashSet};

use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_access::rbac::{Role, RoleHierarchyEdge, RoleTreeNode, UserRole};

use crate::error::DbResult;

/// Methods that manipulate roles via NIST Core RBAC
impl super::Database {
    /// Create a new role.
    pub async fn create_role(&self, role: &Role) -> DbResult<()> {
        Ok(self.roles.create_role(role).await?)
    }

    /// Retrieve a role by its ID.
    pub async fn get_role(&self, role_id: &str) -> DbResult<Role> {
        Ok(self.roles.get_role(role_id).await?)
    }

    /// List all roles (built-in and custom).
    pub async fn list_roles(&self) -> DbResult<Vec<Role>> {
        Ok(self.roles.list_roles().await?)
    }

    /// Update a role's mutable fields (name, description).
    pub async fn update_role(&self, role: &Role) -> DbResult<()> {
        Ok(self.roles.update_role(role).await?)
    }

    /// Delete a role and cascade-remove its PA and UA entries.
    pub async fn delete_role(&self, role_id: &str) -> DbResult<()> {
        Ok(self.roles.delete_role(role_id).await?)
    }

    /// Grant `operations` on `object_id` to `role_id`.
    pub async fn assign_permissions_to_role(
        &self,
        role_id: &str,
        object_id: &str,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        Ok(self
            .roles
            .assign_permissions_to_role(role_id, object_id, operations)
            .await?)
    }

    /// Remove `operations` on `object_id` from `role_id`.
    pub async fn remove_permissions_from_role(
        &self,
        role_id: &str,
        object_id: &str,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        Ok(self
            .roles
            .remove_permissions_from_role(role_id, object_id, operations)
            .await?)
    }

    /// List all permissions assigned to a role.
    pub async fn list_role_permissions(
        &self,
        role_id: &str,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(self.roles.list_role_permissions(role_id).await?)
    }

    /// Assign a role to a user.
    pub async fn assign_role_to_user(
        &self,
        user_id: &str,
        role_id: &str,
        granted_by: &str,
    ) -> DbResult<()> {
        Ok(self
            .roles
            .assign_role_to_user(user_id, role_id, granted_by)
            .await?)
    }

    /// Revoke a role from a user.
    pub async fn revoke_role_from_user(&self, user_id: &str, role_id: &str) -> DbResult<()> {
        Ok(self.roles.revoke_role_from_user(user_id, role_id).await?)
    }

    /// List all roles assigned to a user.
    pub async fn list_user_roles(&self, user_id: &str) -> DbResult<Vec<Role>> {
        Ok(self.roles.list_user_roles(user_id).await?)
    }

    /// List all users assigned to a role.
    pub async fn list_role_users(&self, role_id: &str) -> DbResult<Vec<UserRole>> {
        Ok(self.roles.list_role_users(role_id).await?)
    }

    /// Compute the set of KMIP operations a user can perform on an object
    /// via their assigned roles (does not include direct grants).
    pub async fn role_based_operations_on_object(
        &self,
        uid: &str,
        user: &str,
    ) -> DbResult<HashSet<KmipOperation>> {
        Ok(self
            .roles
            .role_based_operations_on_object(uid, user)
            .await?)
    }

    // ── Hierarchical RBAC ───────────────────────────────────────────────

    /// Add a hierarchy edge: senior inherits all permissions of junior.
    pub async fn add_hierarchy_edge(
        &self,
        senior_role_id: &str,
        junior_role_id: &str,
    ) -> DbResult<()> {
        Ok(self
            .roles
            .add_hierarchy_edge(senior_role_id, junior_role_id)
            .await?)
    }

    /// Remove a hierarchy edge.
    pub async fn remove_hierarchy_edge(
        &self,
        senior_role_id: &str,
        junior_role_id: &str,
    ) -> DbResult<()> {
        Ok(self
            .roles
            .remove_hierarchy_edge(senior_role_id, junior_role_id)
            .await?)
    }

    /// List the direct junior roles of a role.
    pub async fn list_junior_roles(&self, role_id: &str) -> DbResult<Vec<Role>> {
        Ok(self.roles.list_junior_roles(role_id).await?)
    }

    /// List the direct senior roles of a role.
    pub async fn list_senior_roles(&self, role_id: &str) -> DbResult<Vec<Role>> {
        Ok(self.roles.list_senior_roles(role_id).await?)
    }

    /// Return all hierarchy edges.
    pub async fn list_all_hierarchy_edges(&self) -> DbResult<Vec<RoleHierarchyEdge>> {
        Ok(self.roles.list_all_hierarchy_edges().await?)
    }

    /// Get the full hierarchy tree rooted at a role.
    pub async fn get_role_hierarchy_tree(&self, role_id: &str) -> DbResult<RoleTreeNode> {
        Ok(self.roles.get_role_hierarchy_tree(role_id).await?)
    }
}

/// A no-op `RoleStore` for backends that do not yet support RBAC
/// (e.g. Redis-findex). All read operations return empty results;
/// all write operations return an error.
#[cfg(feature = "non-fips")]
pub(crate) struct NoOpRoleStore;

#[cfg(feature = "non-fips")]
#[async_trait::async_trait(?Send)]
impl cosmian_kms_interfaces::RoleStore for NoOpRoleStore {
    async fn create_role(&self, _role: &Role) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn get_role(&self, role_id: &str) -> cosmian_kms_interfaces::InterfaceResult<Role> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(format!(
            "role '{role_id}' not found (RBAC not supported on this backend)"
        )))
    }

    async fn list_roles(&self) -> cosmian_kms_interfaces::InterfaceResult<Vec<Role>> {
        Ok(Vec::new())
    }

    async fn update_role(&self, _role: &Role) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn delete_role(&self, _role_id: &str) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn assign_permissions_to_role(
        &self,
        _role_id: &str,
        _object_id: &str,
        _operations: HashSet<KmipOperation>,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn remove_permissions_from_role(
        &self,
        _role_id: &str,
        _object_id: &str,
        _operations: HashSet<KmipOperation>,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn list_role_permissions(
        &self,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(HashMap::new())
    }

    async fn assign_role_to_user(
        &self,
        _user_id: &str,
        _role_id: &str,
        _granted_by: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn revoke_role_from_user(
        &self,
        _user_id: &str,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC roles are not supported on this database backend".to_owned(),
        ))
    }

    async fn list_user_roles(
        &self,
        _user_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<Vec<Role>> {
        Ok(Vec::new())
    }

    async fn list_role_users(
        &self,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<Vec<UserRole>> {
        Ok(Vec::new())
    }

    async fn role_based_operations_on_object(
        &self,
        _uid: &str,
        _user: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<HashSet<KmipOperation>> {
        Ok(HashSet::new())
    }

    async fn add_hierarchy_edge(
        &self,
        _senior_role_id: &str,
        _junior_role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC hierarchy is not supported on this database backend".to_owned(),
        ))
    }

    async fn remove_hierarchy_edge(
        &self,
        _senior_role_id: &str,
        _junior_role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<()> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC hierarchy is not supported on this database backend".to_owned(),
        ))
    }

    async fn list_junior_roles(
        &self,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<Vec<Role>> {
        Ok(Vec::new())
    }

    async fn list_senior_roles(
        &self,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<Vec<Role>> {
        Ok(Vec::new())
    }

    async fn list_all_hierarchy_edges(
        &self,
    ) -> cosmian_kms_interfaces::InterfaceResult<Vec<RoleHierarchyEdge>> {
        Ok(Vec::new())
    }

    async fn get_role_hierarchy_tree(
        &self,
        _role_id: &str,
    ) -> cosmian_kms_interfaces::InterfaceResult<RoleTreeNode> {
        Err(cosmian_kms_interfaces::InterfaceError::Db(
            "RBAC hierarchy is not supported on this database backend".to_owned(),
        ))
    }
}
