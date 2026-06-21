//! Centralized key resolution pipeline for KMIP operations.
//!
//! This module owns the logic for resolving a `UniqueIdentifier` into a usable key:
//! keyset parsing, oracle (HSM) routing, UID/tag lookup, uniqueness enforcement,
//! and lifecycle validation.
//!
//! The [`resolve_key_for_operation`] function is the main entry point. It is generic
//! over [`CryptoOpSpec`] so that each operation declares its own keyset-mode,
//! state-acceptance, and error-mapping behaviour.
//!
//! ## Architecture
//!
//! ```text
//! UniqueIdentifier
//!   │
//!   ├─ Keyset detection (name / name@version)
//!   │  ├─ Explicit @version → resolve to single UID
//!   │  └─ Bare name:
//!   │     ├─ SingleLatest → resolve latest key
//!   │     └─ TryEach → walk keyset chain
//!   │
//!   ├─ Standard UID / tag resolution
//!   │
//!   ├─ Phase 1: Oracle (HSM) routing
//!   │
//!   └─ Phase 2: Database selection + uniqueness enforcement
//! ```

use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use super::{
    authorization::is_user_authorized, crypto_op::CryptoOpSpec,
    lifecycle::user_can_perform_operation,
};
use crate::{
    core::{
        KMS,
        uid_utils::{
            KeysetVersion, has_prefix, parse_keyset_identifier, resolve_keyset_to_single_uid,
            uids_from_unique_identifier, walk_keyset_chain,
        },
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

// ─── Key selection trait ─────────────────────────────────────────────────────

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
        if !Spec::accepted_states().contains(&owm.effective_state()) {
            continue;
        }

        // 2. Permission check
        let authorized = if Spec::strict_permission_check() {
            // Strict: only exact operation grant (no Get wildcard)
            user_can_perform_operation(&owm, user, &Spec::KMIP_OP, kms).await?
        } else {
            // Lenient: Get grant also authorizes (standard for crypto ops)
            is_user_authorized(&kms.database, owm.id(), user, Spec::KMIP_OP).await?
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

// ─── Keyset mode ─────────────────────────────────────────────────────────────

/// Determines how a keyset reference (bare name without `@version`) is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysetMode {
    /// Use only the latest key in the keyset (for encrypt, sign, MAC).
    SingleLatest,
    /// Try each key in the chain from newest to oldest (for decrypt, verify).
    TryEach,
}

// ─── Resolution result ───────────────────────────────────────────────────────

/// Result of key resolution for a cryptographic operation.
pub(super) enum ResolvedKey {
    /// Key lives on an external crypto oracle (HSM / external key store).
    /// The caller dispatches to the oracle using the `uid` and `prefix`.
    Oracle { uid: String, prefix: String },
    /// Key is in the local database: selected, Active, lifecycle-validated.
    /// NOT yet unwrapped — the caller handles unwrapping based on operation needs.
    Local(Box<ObjectWithMetadata>),
    /// A keyset chain: ordered list of UIDs from newest to oldest.
    /// The caller tries each key in order until one succeeds.
    Keyset(Vec<String>),
}

// ─── Oracle selection ────────────────────────────────────────────────────────

/// Collect the single eligible crypto-oracle UID for a cryptographic operation.
///
/// Iterates over `candidate_uids`, retains those that carry a recognized prefix (oracle
/// keys), and filters out any for which the current `user` lacks authorization.
///
/// Returns:
/// * `Ok(None)` — no oracle UID is eligible; the caller should fall through to the standard
///   database path.
/// * `Ok(Some((uid, prefix)))` — exactly one oracle UID is eligible; use it.
/// * `Err(KmsError::InvalidRequest)` — more than one oracle UID is eligible (ambiguous).
async fn select_eligible_oracle_uid(
    operation: KmipOperation,
    op_name: &str,
    candidate_uids: &HashSet<String>,
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
    user: &str,
) -> KResult<Option<(String, String)>> {
    let mut eligible: Vec<(String, String)> = Vec::new();
    for uid in candidate_uids {
        if let Some(prefix) = has_prefix(uid) {
            if !is_user_authorized(&kms.database, uid, user, operation).await? {
                continue;
            }
            eligible.push((uid.clone(), prefix.to_owned()));
        }
    }
    match eligible.len() {
        0 => Ok(None),
        1 => Ok(eligible.into_iter().next()),
        n => {
            let ids: Vec<&str> = eligible.iter().map(|(uid, _)| uid.as_str()).collect();
            Err(KmsError::InvalidRequest(format!(
                "{op_name}: identifier {unique_identifier} resolves to {n} valid oracle keys \
                 {ids:?}; use a unique identifier",
            )))
        }
    }
}

// ─── Main resolution pipeline ────────────────────────────────────────────────

/// Resolve the key for a cryptographic operation using the [`CryptoOpSpec`] trait.
///
/// Performs the entire key selection pipeline generically:
/// 1. Checks if the identifier is a keyset reference (name or name@version).
/// 2. Resolves UIDs from the `unique_identifier`.
/// 3. Attempts oracle (HSM) routing.
/// 4. Selects the key from the database with `Op::is_key_eligible`.
/// 5. Applies error mapping via `Op::map_selection_error`.
/// 6. Enforces process window constraints (`ProcessStartDate` / `ProtectStopDate`).
///
/// Returns [`ResolvedKey::Oracle`] for HSM keys, [`ResolvedKey::Local`] for DB keys,
/// or [`ResolvedKey::Keyset`] for try-each keyset chains.
/// Local keys are NOT unwrapped — `perform_crypto_operation` handles unwrapping.
pub(super) async fn resolve_key_for_operation<Op: CryptoOpSpec>(
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
    user: &str,
) -> KResult<ResolvedKey> {
    let uid_str = unique_identifier
        .as_str()
        .context("The unique identifier must be a string")?;

    // ── Keyset detection ─────────────────────────────────────────────────────
    if let Some(keyset_ref) = parse_keyset_identifier(uid_str) {
        // Explicit @version → resolve to a single key
        match &keyset_ref.version {
            KeysetVersion::Latest | KeysetVersion::First | KeysetVersion::Generation(_) => {
                if let Some(uid) = resolve_keyset_to_single_uid(&keyset_ref, kms, user).await? {
                    let owm = kms.database.retrieve_object(&uid).await?.ok_or_else(|| {
                        KmsError::ItemNotFound(format!(
                            "{}: keyset key not found: {uid}",
                            Op::OP_NAME
                        ))
                    })?;
                    owm.check_process_window()?;
                    return Ok(ResolvedKey::Local(Box::new(owm)));
                }
                // Keyset name not found in DB — fall through to normal UID resolution
            }
            KeysetVersion::Bare => {
                // Bare keyset name: behavior depends on operation's keyset_mode
                match Op::keyset_mode() {
                    KeysetMode::SingleLatest => {
                        if let Some(uid) =
                            resolve_keyset_to_single_uid(&keyset_ref, kms, user).await?
                        {
                            let owm =
                                kms.database.retrieve_object(&uid).await?.ok_or_else(|| {
                                    KmsError::ItemNotFound(format!(
                                        "{}: keyset key not found: {uid}",
                                        Op::OP_NAME
                                    ))
                                })?;
                            owm.check_process_window()?;
                            return Ok(ResolvedKey::Local(Box::new(owm)));
                        }
                        // Not a keyset → fall through to normal path
                    }
                    KeysetMode::TryEach => {
                        let chain = walk_keyset_chain(&keyset_ref.name, kms, user).await?;
                        if !chain.is_empty() {
                            return Ok(ResolvedKey::Keyset(chain));
                        }
                        // Not a keyset → fall through to normal path
                    }
                }
            }
        }
    }

    // ── Standard UID / tag resolution ────────────────────────────────────────
    let uids = uids_from_unique_identifier(unique_identifier, kms)
        .await
        .context(Op::OP_NAME)?;

    // Phase 1 — Oracle (HSM / prefix) routing.
    if let Some((uid, prefix)) = select_eligible_oracle_uid(
        Op::KMIP_OP,
        Op::OP_NAME,
        &uids,
        unique_identifier,
        kms,
        user,
    )
    .await?
    {
        return Ok(ResolvedKey::Oracle { uid, prefix });
    }

    // Phase 2 — Standard database path: fetch candidates, filter, enforce uniqueness.
    let mut candidates = Vec::new();
    for uid in &uids {
        if has_prefix(uid).is_some() {
            continue;
        }
        if let Some(owm) = kms.database.retrieve_object(uid).await? {
            candidates.push(owm);
        }
    }
    let uid_display = unique_identifier.to_string();
    let owm = select_unique_key::<Op, _>(candidates, &uid_display, kms, user, |_| Ok(()))
        .await
        .map_err(|e| Op::map_selection_error(e, unique_identifier, user))?;

    // Lifecycle enforcement: always check process window.
    owm.check_process_window()?;

    Ok(ResolvedKey::Local(Box::new(owm)))
}
