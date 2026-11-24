use std::collections::{HashMap, HashSet};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_interfaces::UserId;
use cosmian_logger::reexport::tracing;

use super::Database;
use crate::{
    CeremonyPayload,
    error::{DbError, DbResult},
};

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

    /// Record that the Crypto Officer split-key ceremony has been completed.
    ///
    /// **Per-user model**: multiple CO users can be simultaneously active. This call
    /// only touches the record for `activated_by` — no other user's activation is
    /// affected. Each CO candidate activates independently by running `JoinSplitKey`.
    pub async fn activate_crypto_officer_ceremony(
        &self,
        activated_by: &str,
        participants: &[String],
        key_hash: &str,
    ) -> DbResult<()> {
        let sealed =
            self.seal_ceremony_record(activated_by, participants, key_hash, "crypto_officer")?;
        // The trait implementation performs revoke+insert in one atomic transaction,
        // scoped to `activated_by` only — idempotent re-activation for the same user.
        Ok(self
            .permissions
            .activate_crypto_officer_ceremony(&sealed, activated_by, activated_by)
            .await?)
    }

    /// Returns `true` if **any** user currently has an active Crypto Officer ceremony record.
    pub async fn is_crypto_officer_activated(&self) -> DbResult<bool> {
        Ok(self.permissions.is_any_crypto_officer_activated().await?)
    }

    /// Returns `true` if `user` has their own active Crypto Officer ceremony record.
    ///
    /// Other users in `crypto_officer_users` may simultaneously be active COs with
    /// their own independent activation records.
    pub async fn is_crypto_officer_activated_by(&self, user: &str) -> DbResult<bool> {
        let sealed_opt = self
            .permissions
            .get_crypto_officer_activation_by(user)
            .await?;
        self.verify_ceremony_record(sealed_opt, "crypto_officer", user)
    }

    /// Revoke `activated_by`'s active Crypto Officer ceremony record.
    ///
    /// `revoked_by` is stored in the audit column (who issued the revocation).
    /// Only `activated_by`'s record is touched — all other users' records remain active.
    pub async fn revoke_crypto_officer_activation(
        &self,
        revoked_by: &str,
        activated_by: &str,
    ) -> DbResult<()> {
        Ok(self
            .permissions
            .revoke_crypto_officer_activation(revoked_by, activated_by)
            .await?)
    }
}

impl Database {
    // ── CRL persistence ─────────────────────────────────────────────────────

    /// Persist (or replace) the most recently generated CRL for `issuer_id`.
    pub async fn upsert_crl(
        &self,
        issuer_id: &str,
        crl_der: &[u8],
        crl_number: u64,
        generated_at: &str,
        next_update: &str,
    ) -> DbResult<()> {
        Ok(self
            .permissions
            .upsert_crl(issuer_id, crl_der, crl_number, generated_at, next_update)
            .await?)
    }

    /// Retrieve the persisted CRL DER bytes and generation timestamp for `issuer_id`.
    pub async fn get_crl(&self, issuer_id: &str) -> DbResult<Option<(Vec<u8>, String)>> {
        Ok(self.permissions.get_crl(issuer_id).await?)
    }

    /// List all issuer IDs with their stored `next_update` timestamps.
    pub async fn list_crl_issuers(&self) -> DbResult<Vec<(String, String)>> {
        Ok(self.permissions.list_crl_issuers().await?)
    }

    /// Return the highest `crl_number` across all stored CRLs, or `None` when none exist.
    ///
    /// Called once during [`KMS::instantiate`] to seed the CRL sequence counter so that
    /// CRL Numbers are strictly monotonically increasing across server restarts
    /// (RFC 5280 §5.2.3).
    pub async fn get_max_crl_number(&self) -> DbResult<Option<u64>> {
        Ok(self.permissions.get_max_crl_number().await?)
    }
}

/// Private helpers for ceremony record encryption.
impl Database {
    /// Seal a ceremony payload for a given role.
    ///
    /// Returns `Err` when `ceremony_keys` is not configured (server misconfiguration).
    fn seal_ceremony_record(
        &self,
        activated_by: &str,
        participants: &[String],
        key_hash: &str,
        role: &str,
    ) -> DbResult<String> {
        let keys = self.ceremony_keys.as_ref().ok_or_else(|| {
            DbError::DatabaseError(
                "ceremony_secret not configured: cannot seal ceremony record".to_owned(),
            )
        })?;
        let payload = CeremonyPayload {
            activated_by: activated_by.to_owned(),
            participants: participants.to_vec(),
            key_hash: key_hash.to_owned(),
        };
        keys.seal(&payload, role)
    }

    /// Verify sealed record integrity. Returns `true` if a valid sealed record exists and
    /// verifies against this node's `ceremony_keys` and was sealed for `user`, `false` if no
    /// record exists, **or** if the record fails GCM verification (a tampered record, or — in a
    /// multi-region deployment — a replicated record sealed with a different
    /// `ceremony_secret`/`ceremony_key_id` than this node's), **or** if it was sealed for another
    /// user (a record moved between rows), or `Err` only for a genuine local misconfiguration
    /// (`ceremony_keys` unset).
    fn verify_ceremony_record(
        &self,
        sealed_opt: Option<String>,
        role: &str,
        user: &str,
    ) -> DbResult<bool> {
        match sealed_opt {
            None => Ok(false),
            Some(sealed) => {
                let keys = self.ceremony_keys.as_ref().ok_or_else(|| {
                    DbError::DatabaseError(
                        "ceremony_secret not configured: cannot verify ceremony record".to_owned(),
                    )
                })?;
                // Unseal verifies GCM tag. Fail secure: a verification failure (tampered record,
                // or a cross-region ceremony_secret/ceremony_key_id mismatch) means this node
                // cannot confirm the ceremony is valid — treat as "not active" rather than
                // propagating a hard error, mirroring
                // dispatch.rs::check_role_permission's existing fallback for the identical
                // underlying condition.
                match keys.unseal(&sealed, role) {
                    Ok(payload) if payload.activated_by == user => Ok(true),
                    Ok(_) => {
                        tracing::error!(
                            target: "audit",
                            role,
                            user,
                            "ceremony record was sealed for another user (record moved between \
                             rows); treating as inactive"
                        );
                        Ok(false)
                    }
                    Err(DbError::CryptographicError(e)) => {
                        tracing::error!(
                            target: "audit",
                            role,
                            user,
                            error = %e,
                            "ceremony record verification failed (tampered record, or \
                             ceremony_keys mismatch across regions); treating as inactive"
                        );
                        Ok(false)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use std::{collections::HashMap, num::NonZeroUsize, path::Path, time::Duration};

    use tempfile::TempDir;

    use super::Database;
    use crate::{
        CeremonyKeys,
        core::{CacheParams, MainDbParams},
        error::DbResult,
    };

    async fn ceremony_db(dir: &Path) -> DbResult<Database> {
        Database::instantiate(
            &MainDbParams::Sqlite(dir.to_path_buf(), None),
            false,
            HashMap::new(),
            CacheParams {
                max_age: Duration::from_secs(1),
                max_size: NonZeroUsize::new(100).expect("non-zero"),
                max_ttl: None,
                disabled: false,
            },
            None,
            Some(std::sync::Arc::new(CeremonyKeys::derive(&[7_u8; 32])?)),
        )
        .await
    }

    /// Tamper with the `SQLite` file behind the database's back, as a database writer would.
    fn sqlite_exec(dir: &Path, sql: &str) -> DbResult<()> {
        rusqlite::Connection::open(dir.join("kms.db"))?.execute(sql, [])?;
        Ok(())
    }

    #[tokio::test]
    async fn ceremony_record_copied_to_another_user_is_inactive() -> DbResult<()> {
        let dir = TempDir::new()?;
        let db = ceremony_db(dir.path()).await?;
        db.activate_crypto_officer_ceremony("alice", &["p1".to_owned(), "p2".to_owned()], "hash")
            .await?;
        let sealed = db
            .permissions
            .get_crypto_officer_activation_by("alice")
            .await?
            .expect("alice has a record");
        // A database writer replays alice's record under bob.
        db.permissions
            .activate_crypto_officer_ceremony(&sealed, "bob", "bob")
            .await?;
        assert!(db.is_crypto_officer_activated_by("alice").await?);
        assert!(!db.is_crypto_officer_activated_by("bob").await?);
        Ok(())
    }

    #[tokio::test]
    async fn revoked_ceremony_record_stays_inactive_when_revocation_is_cleared() -> DbResult<()> {
        let dir = TempDir::new()?;
        let db = ceremony_db(dir.path()).await?;
        db.activate_crypto_officer_ceremony("alice", &["p1".to_owned()], "hash")
            .await?;
        db.revoke_crypto_officer_activation("alice", "alice")
            .await?;
        assert!(!db.is_crypto_officer_activated_by("alice").await?);
        sqlite_exec(
            dir.path(),
            "UPDATE crypto_officer_activations SET revoked_at = NULL, revoked_by = NULL",
        )?;
        assert!(!db.is_crypto_officer_activated_by("alice").await?);
        Ok(())
    }

    #[tokio::test]
    async fn ceremony_records_revoked_before_upgrade_are_tombstoned_at_startup() -> DbResult<()> {
        let dir = TempDir::new()?;
        let db = ceremony_db(dir.path()).await?;
        db.activate_crypto_officer_ceremony("alice", &["p1".to_owned()], "hash")
            .await?;
        // An older KMS revokes by setting `revoked_at` only, leaving the sealed record.
        sqlite_exec(
            dir.path(),
            "UPDATE crypto_officer_activations SET revoked_at = CURRENT_TIMESTAMP",
        )?;
        drop(db);
        let db = ceremony_db(dir.path()).await?;
        sqlite_exec(
            dir.path(),
            "UPDATE crypto_officer_activations SET revoked_at = NULL, revoked_by = NULL",
        )?;
        assert!(!db.is_crypto_officer_activated_by("alice").await?);
        Ok(())
    }
}
