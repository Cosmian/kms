use std::collections::{HashMap, HashSet};

use cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation};
use cosmian_kms_interfaces::UserId;

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
        let start = std::time::Instant::now();
        let result = self.permissions.list_user_operations_granted(user).await;
        if let Some(ref rec) = self.recorder {
            let outcome = if result.is_ok() { "success" } else { "error" };
            rec.record_operation(
                "list_access",
                self.kind,
                outcome,
                start.elapsed().as_secs_f64(),
            );
        }
        Ok(result?)
    }

    /// List all the KMIP operations granted per `user` on the given object
    /// This is called by the owner only
    pub async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(self.permissions.list_object_operations_granted(uid).await?)
    }

    /// Grant the ability to `user` to perform the KMIP `operations`
    /// on the object identified by its `uid`
    pub async fn grant_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        Ok(self
            .permissions
            .grant_operations(uid, user, operations)
            .await?)
    }

    /// Remove the ability to `user` to perform the `operations`
    /// on the object identified by its `uid`
    pub async fn remove_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> DbResult<()> {
        Ok(self
            .permissions
            .remove_operations(uid, user, operations)
            .await?)
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
        Ok(self
            .permissions
            .list_user_operations_on_object(uid, user, no_inherited_access)
            .await?)
    }

    /// Record that the Crypto Officer split-key ceremony has been completed.
    ///
    /// Revokes any existing active ceremony record before inserting the new one,
    /// ensuring at most one active record exists at any time.
    pub async fn activate_crypto_officer_ceremony(
        &self,
        activated_by: &str,
        participants: &[String],
        key_hash: &str,
    ) -> DbResult<()> {
        // Revoke any existing active record to prevent multiple active rows.
        // Failure is expected when no prior activation exists.
        drop(
            self.permissions
                .revoke_crypto_officer_activation(activated_by)
                .await,
        );
        let sealed =
            self.seal_ceremony_record(activated_by, participants, key_hash, "crypto_officer")?;
        Ok(self
            .permissions
            .activate_crypto_officer_ceremony(&sealed)
            .await?)
    }

    /// Returns `true` if there is an active (not revoked) Crypto Officer ceremony record.
    pub async fn is_crypto_officer_activated(&self) -> DbResult<bool> {
        let sealed_opt = self.permissions.get_crypto_officer_activation().await?;
        self.verify_ceremony_record(sealed_opt, "crypto_officer")
    }

    /// Returns `true` if there is an active Crypto Officer ceremony record **and** the
    /// `activated_by` field of that record equals `user`.
    ///
    /// This ensures that only the specific user who ran `JoinSplitKey` is granted the
    /// `CryptoOfficer` role — other users in `crypto_officer_users` remain Operators until
    /// they complete their own ceremony.
    pub async fn is_crypto_officer_activated_by(&self, user: &str) -> DbResult<bool> {
        let sealed_opt = self.permissions.get_crypto_officer_activation().await?;
        match sealed_opt {
            None => Ok(false),
            Some(sealed) => {
                let keys = self.ceremony_keys.as_ref().ok_or_else(|| {
                    DbError::DatabaseError(
                        "ceremony_secret not configured: cannot verify ceremony record".to_owned(),
                    )
                })?;
                let payload = keys.unseal(&sealed, "crypto_officer")?;
                Ok(payload.activated_by == user)
            }
        }
    }

    /// Revoke the active Crypto Officer ceremony record (set `revoked_at` to now).
    pub async fn revoke_crypto_officer_activation(&self, revoked_by: &str) -> DbResult<()> {
        Ok(self
            .permissions
            .revoke_crypto_officer_activation(revoked_by)
            .await?)
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

    /// Verify sealed record integrity. Returns `true` if a valid sealed record exists,
    /// `false` if no record, or `Err` if the record is tampered.
    fn verify_ceremony_record(&self, sealed_opt: Option<String>, role: &str) -> DbResult<bool> {
        match sealed_opt {
            None => Ok(false),
            Some(sealed) => {
                let keys = self.ceremony_keys.as_ref().ok_or_else(|| {
                    DbError::DatabaseError(
                        "ceremony_secret not configured: cannot verify ceremony record".to_owned(),
                    )
                })?;
                // Unseal verifies GCM tag — tampered records produce Err here.
                keys.unseal(&sealed, role)?;
                Ok(true)
            }
        }
    }
}
