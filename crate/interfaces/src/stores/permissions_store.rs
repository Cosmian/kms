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

    /// Store a sealed (AES-256-GCM encrypted) crypto officer ceremony activation record.
    ///
    /// `activated_by` is stored as a plaintext column to support unique-per-user
    /// partial indexing (`WHERE revoked_at IS NULL`), preventing duplicate active
    /// records for the same user at the database level.
    async fn activate_crypto_officer_ceremony(
        &self,
        sealed_record: &str,
        activated_by: &str,
    ) -> InterfaceResult<()>;

    /// Retrieve the active (non-revoked) sealed crypto officer ceremony record, if any.
    async fn get_crypto_officer_activation(&self) -> InterfaceResult<Option<String>>;

    /// Revoke the active crypto officer ceremony record (set `revoked_at` to now).
    /// No-op if no active record exists.
    async fn revoke_crypto_officer_activation(&self, revoked_by: &str) -> InterfaceResult<()>;

    // ── CRL persistence (RFC 5280 §5) ──────────────────────────────────────

    /// Persist (or replace) the most recently generated CRL for `issuer_id`.
    ///
    /// Called by `generate_crl` after every successful CRL signing so the
    /// public CDP endpoint can resume serving after a server restart without
    /// requiring a manual re-generation.
    ///
    /// # Arguments
    /// * `issuer_id`    — UID of the CA certificate (primary key)
    /// * `crl_der`      — DER-encoded signed CRL bytes
    /// * `crl_number`   — Monotonically increasing CRL sequence number (RFC 5280 §5.2.3)
    /// * `generated_at` — ISO-8601 UTC timestamp of generation
    /// * `next_update`  — ISO-8601 UTC timestamp of expiry
    async fn upsert_crl(
        &self,
        issuer_id: &str,
        crl_der: &[u8],
        crl_number: u64,
        generated_at: &str,
        next_update: &str,
    ) -> InterfaceResult<()>;

    /// Retrieve the persisted CRL DER bytes and generation timestamp for `issuer_id`.
    ///
    /// Returns `None` when no CRL has ever been generated for this issuer.
    async fn get_crl(&self, issuer_id: &str) -> InterfaceResult<Option<(Vec<u8>, String)>>;

    /// List all issuer IDs with their stored `next_update` timestamps.
    ///
    /// Used by the background CRL refresh scheduler to identify CRLs that are
    /// expiring soon without fetching the full DER bytes for every CA.
    async fn list_crl_issuers(&self) -> InterfaceResult<Vec<(String, String)>>;

    /// Return the highest `crl_number` stored across all issuers, or `None` when
    /// no CRL has ever been persisted.
    ///
    /// Used on startup to seed the monotonically-increasing CRL sequence counter
    /// so that CRL Numbers remain strictly greater than any previously issued
    /// number across server restarts (RFC 5280 §5.2.3).
    async fn get_max_crl_number(&self) -> InterfaceResult<Option<u64>>;
}
