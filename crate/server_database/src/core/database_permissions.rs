use std::collections::{HashMap, HashSet};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_interfaces::UserId;

use super::Database;
use crate::error::DbResult;

/// Methods that manipulate permissions
impl Database {
    /// List all the KMIP operations granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, `is_wrapped`)
    /// where `operations` is a list of KMIP operations that `user` can perform on the object
    pub async fn list_user_operations_granted(
        &self,
        user: &UserId,
    ) -> DbResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        self.record("list_user_ops_granted", async move {
            Ok(self.permissions.list_user_operations_granted(user).await?)
        })
        .await
    }

    /// List all the KMIP operations granted per `user` on the given object
    /// This is called by the owner only
    pub async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        self.record("list_object_ops_granted", async move {
            Ok(self.permissions.list_object_operations_granted(uid).await?)
        })
        .await
    }

    /// Grant the ability to `user` to perform the KMIP `operations`
    /// on the object identified by its `uid`
    pub async fn grant_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        self.record("grant_ops", async move {
            Ok(self
                .permissions
                .grant_operations(uid, user, operations)
                .await?)
        })
        .await
    }

    /// Remove the ability to `user` to perform the `operations`
    /// on the object identified by its `uid`
    pub async fn remove_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        self.record("remove_ops", async move {
            Ok(self
                .permissions
                .remove_operations(uid, user, operations)
                .await?)
        })
        .await
    }

    /// List all the operations that have been granted to a user on an object
    ///
    /// These operations may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    pub async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &UserId,
        no_inherited_access: bool,
    ) -> DbResult<HashSet<KmipOperation>> {
        self.record("list_user_ops_on_object", async move {
            Ok(self
                .permissions
                .list_user_operations_on_object(uid, user, no_inherited_access)
                .await?)
        })
        .await
    }
}
