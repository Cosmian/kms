use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};

use crate::{InterfaceResult, UserId};

/// Trait that the stores must implement to store permissions
#[async_trait(?Send)]
pub trait PermissionsStore {
    /// List all the KMIP operations granted to the `user`
    /// on all the objects in the database
    /// (i.e. the objects for which `user` is not the owner)
    /// The result is a list of tuples (uid, owner, state, operations, `is_wrapped`)
    /// where `operations` is a list of operations that `user` can perform on the object
    async fn list_user_operations_granted(
        &self,
        user: &UserId,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>>;

    /// List all the KMIP operations granted per `user`
    /// This is called by the owner only
    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>>;

    /// Grant to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn grant_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()>;

    /// Remove to `user` the ability to perform the KMIP `operations`
    /// on the object identified by its `uid`
    async fn remove_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()>;

    /// List all the KMIP operations that have been granted to a user on an object
    ///
    /// These operations may have been directly granted or via the wildcard user
    /// unless `no_inherited_access` is set to `true`
    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &UserId,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>>;

    // ── Crypto Officer ceremony ─────────────────────────────────────────────

    /// Atomically revoke any existing active ceremony record and insert a new one.
    ///
    /// The revoke and insert **must** be performed in a single database transaction
    /// to close the TOCTOU race where two concurrent activations could both slip
    /// through the revoke window and leave two active rows.
    ///
    /// `activated_by` is stored as a plaintext column to support unique-per-user
    /// partial indexing (`WHERE revoked_at IS NULL`), preventing duplicate active
    /// records for the same user at the database level.
    ///
    /// `revoked_by` is written to the `revoked_by` audit column of any prior active
    /// record (typically equals `activated_by` — the activator implicitly revokes
    /// the previous record by replacing it).
    async fn activate_crypto_officer_ceremony(
        &self,
        sealed_record: &str,
        activated_by: &str,
        revoked_by: &str,
    ) -> InterfaceResult<()>;

    /// Retrieve the active (non-revoked) sealed crypto officer ceremony record, if any.
    async fn get_crypto_officer_activation(&self) -> InterfaceResult<Option<String>>;

    /// Revoke the active crypto officer ceremony record (set `revoked_at` to now).
    /// No-op if no active record exists.
    async fn revoke_crypto_officer_activation(&self, revoked_by: &str) -> InterfaceResult<()>;
}
