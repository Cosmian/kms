use std::collections::{HashMap, HashSet};

use cosmian_kmip::kmip::{kmip_types::StateEnumeration, KmipOperation};

use super::Database;
use crate::{error::DbResult, stores::ExtraStoreParams};

/// Methods that manipulate permissions
impl Database {
    /// List all the KMIP operations granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, `is_wrapped`)
    /// where `operations` is a list of KMIP operations that `user` can perform on the object
    pub async fn list_user_operations_granted(
        &self,
        user: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>> {
        self.permissions
            .list_user_operations_granted(user, params)
            .await
    }

    /// List all the KMIP operations granted per `user` on the given object
    /// This is called by the owner only
    pub async fn list_object_operations_granted(
        &self,
        uid: &str,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        self.permissions
            .list_object_operations_granted(uid, params)
            .await
    }

    /// Grant the ability to `user` to perform the KMIP `operations`
    /// on the object identified by its `uid`
    pub async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        self.permissions
            .grant_operations(uid, user, operations, params)
            .await
    }

    /// Remove the ability to `user` to perform the `operations`
    /// on the object identified by its `uid`
    pub async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        self.permissions
            .remove_operations(uid, user, operations, params)
            .await
    }

    /// List all the operations that have been granted to a user on an object
    ///
    /// These operations may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    pub async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<KmipOperation>> {
        self.permissions
            .list_user_operations_on_object(uid, user, no_inherited_access, params)
            .await
    }
}
