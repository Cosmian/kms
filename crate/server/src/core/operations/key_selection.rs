//! Shared key-selection trait and generic function.
//!
//! Both cryptographic operations (`Encrypt`, `Decrypt`, `Sign`, …) and rotation
//! operations (`ReKey`, `ReKeyKeyPair`) need to select exactly one eligible key
//! from a set of candidates. This module factors the common pipeline:
//!
//! **state filter → permission check → eligibility → extra validation → uniqueness**
//!
//! into a single generic function [`select_unique_key`] parameterized by the
//! [`KeySelectionSpec`] trait.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{kmip_0::kmip_types::State, kmip_2_1::KmipOperation},
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use super::key_ops::{CryptoOpSpec, DatabaseOps, ObjectWithMetadataOps};
use crate::{core::KMS, error::KmsError, result::KResult};

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Declarative specification for key selection shared across all KMIP operations.
///
/// Implemented by:
/// - Crypto operation marker structs (via the `CryptoOpSpec` supertrait relationship)
/// - Rekey operation structs (`SymmetricRekey`, `KeypairRekey`)
pub(crate) trait KeySelectionSpec {
    /// Human-readable operation name for error messages (e.g. `"Encrypt"`, `"ReKey"`).
    const OP_NAME: &'static str;

    /// The KMIP operation used for permission checks.
    const KMIP_OP: KmipOperation;

    /// Key states accepted by this operation.
    fn accepted_states() -> &'static [State];

    /// Whether permission checks require an exact operation grant.
    ///
    /// - `false` (default): a `Get` grant also authorizes the operation (crypto ops).
    /// - `true`: only an explicit grant of [`Self::KMIP_OP`] authorizes (rekey, destructive ops).
    fn strict_permission_check() -> bool {
        false
    }

    /// Determine if the managed object is eligible (object type + usage mask).
    fn is_key_eligible(owm: &ObjectWithMetadata, vendor_id: &str) -> bool;
}

// ─── Blanket impl for all CryptoOpSpec types ─────────────────────────────────

/// Every `CryptoOpSpec` implementor automatically satisfies `KeySelectionSpec`.
///
/// This avoids duplicate trait implementations for `EncryptOp`, `DecryptOp`, etc.
impl<T: CryptoOpSpec> KeySelectionSpec for T {
    const KMIP_OP: KmipOperation = T::KMIP_OP;
    const OP_NAME: &'static str = T::OP_NAME;

    fn accepted_states() -> &'static [State] {
        T::accepted_states()
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, vendor_id: &str) -> bool {
        <T as CryptoOpSpec>::is_key_eligible(owm, vendor_id)
    }
}

// ─── Generic selection function ──────────────────────────────────────────────

/// Select exactly one key from pre-fetched candidates using the [`KeySelectionSpec`] pipeline.
///
/// Applies the following filters in order:
/// 1. **State** — `Spec::accepted_states()`
/// 2. **Permission** — `is_user_authorized_for_operation` with `Spec::KMIP_OP`
/// 3. **Eligibility** — `Spec::is_eligible()`
/// 4. **Extra validation** — caller-supplied closure for operation-specific checks
///    (e.g. keyset-latest guard, crypto-param change rejection)
///
/// Enforces uniqueness:
/// - 0 eligible → `KmsError::ItemNotFound` or `KmsError::Unauthorized`
/// - 1 eligible → `Ok(ObjectWithMetadata)`
/// - \>1 eligible → `KmsError::InvalidRequest` (ambiguous)
///
/// # Parameters
///
/// - `candidates`: Pre-fetched objects (from `retrieve_eligible_keys` or per-UID fetch).
/// - `uid_display`: Display string for the identifier (used in error messages).
/// - `kms`: Server state.
/// - `user`: Requesting user.
/// - `extra_validation`: Sync closure applied after eligibility; return `Ok(())` to accept,
///   `Err(...)` to reject with a hard error (propagated immediately, not silently skipped).
pub(crate) async fn select_unique_key<Spec, F>(
    candidates: Vec<ObjectWithMetadata>,
    uid_display: &str,
    kms: &KMS,
    user: &str,
    extra_validation: F,
) -> KResult<ObjectWithMetadata>
where
    Spec: KeySelectionSpec,
    F: Fn(&ObjectWithMetadata) -> KResult<()>,
{
    let mut eligible: Vec<ObjectWithMetadata> = Vec::new();
    let mut found_but_no_permission = false;

    for owm in candidates {
        // 1. State filter
        if !Spec::accepted_states().contains(&owm.get_effective_state()?) {
            continue;
        }

        // 2. Permission check
        let authorized = if Spec::strict_permission_check() {
            // Strict: only exact operation grant (no Get wildcard)
            owm.user_can_perform_operation(user, &Spec::KMIP_OP, kms)
                .await?
        } else {
            // Lenient: Get grant also authorizes (standard for crypto ops)
            kms.database
                .is_user_authorized_for_operation(owm.id(), user, Spec::KMIP_OP)
                .await?
        };
        if !authorized {
            found_but_no_permission = true;
            continue;
        }

        // 3. Eligibility (object type + usage mask)
        if !Spec::is_key_eligible(&owm, kms.vendor_id()) {
            continue;
        }

        // 4. Extra validation (hard error on failure — not skipped)
        extra_validation(&owm)?;

        eligible.push(owm);
    }

    match eligible.len() {
        1 => eligible
            .into_iter()
            .next()
            .ok_or_else(|| KmsError::ItemNotFound("unreachable: len == 1".to_owned())),
        0 => Err(if found_but_no_permission {
            KmsError::Unauthorized(format!(
                "{}: user {user} does not have permission to use key: {uid_display}",
                Spec::OP_NAME,
            ))
        } else {
            KmsError::ItemNotFound(format!(
                "{}: no valid key found for identifier: {uid_display}",
                Spec::OP_NAME,
            ))
        }),
        n => {
            let ids: Vec<&str> = eligible.iter().map(ObjectWithMetadata::id).collect();
            Err(KmsError::InvalidRequest(format!(
                "{}: identifier '{uid_display}' resolves to {n} valid keys {ids:?}; \
                 use a unique identifier",
                Spec::OP_NAME,
            )))
        }
    }
}
