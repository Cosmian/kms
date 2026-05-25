use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_types::{UniqueIdentifier, UsageLimitsUnit},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use super::{DatabaseOps, ObjectWithMetadataOps};
use crate::{
    core::{
        KMS,
        uid_utils::{has_prefix, uids_from_unique_identifier},
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

// ─── Generic crypto operation key resolution ─────────────────────────────────

/// Result of key resolution for a cryptographic operation.
pub(crate) enum ResolvedKey {
    /// Key lives on an external crypto oracle (HSM / external key store).
    /// The caller dispatches to the oracle using the `uid` and `prefix`.
    Oracle { uid: String, prefix: String },
    /// Key is in the local database: selected, Active, lifecycle-validated.
    /// NOT yet unwrapped — the caller handles unwrapping based on operation needs.
    Local(Box<ObjectWithMetadata>),
}

/// Check whether a managed object's usage mask permits the given operation.
///
/// Resolves the object's effective attributes (prefers the object's own key-block
/// attributes, falls back to externally-stored metadata) and tests against the
/// required `CryptographicUsageMask` flag.
///
/// # `lenient` mode
///
/// When `true`, a **missing** usage mask (`None`) is treated as "allowed".
/// This backward-compatibility mode is used for Certificates and Public Keys that
/// were imported without a usage mask.
///
/// When `false`, a missing mask means the key is **rejected**.
pub(crate) fn has_usage_mask(
    owm: &ObjectWithMetadata,
    required: CryptographicUsageMask,
    lenient: bool,
) -> bool {
    let attributes = owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes());
    if lenient && attributes.cryptographic_usage_mask.is_none() {
        return true;
    }
    attributes
        .is_usage_authorized_for(required)
        .unwrap_or(false)
}

/// Declarative specification for KMIP cryptographic operations.
///
/// Implemented by zero-sized marker types (one per operation). A generic
/// `perform_crypto_operation` function uses these associated constants and methods
/// to perform oracle routing, database key selection, lifecycle enforcement,
/// policy checks, usage-limit accounting, and dispatches to the operation-specific
/// execution logic.
///
/// # Design
///
/// Each KMIP cryptographic operation (`Encrypt`, `Decrypt`, `Sign`, `SignatureVerify`,
/// `MAC`, `MACVerify`) implements this trait on a unit struct.
pub(crate) trait CryptoOpSpec {
    /// Human-readable operation name for error messages (e.g. `"Encrypt"`, `"Sign"`).
    const OP_NAME: &'static str;

    /// The KMIP operation enum value used for permission checks.
    const KMIP_OP: KmipOperation;

    /// The KMIP request type for this operation.
    type Request: Send + Sync;

    /// The KMIP response type for this operation.
    type Response: Send;

    /// Extract the `UniqueIdentifier` from the typed request.
    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier>;

    /// Compute the data length for `UsageLimits` enforcement.
    ///
    /// The meaning varies per operation:
    /// - Encrypt: plaintext length
    /// - Decrypt: ciphertext length
    /// - Sign/SignatureVerify: max(data, `digested_data`) length
    /// - MAC/MACVerify: data length
    fn usage_data_len(request: &Self::Request) -> usize;

    /// Determine if the given managed object is eligible for this operation.
    ///
    /// Checks object type and `CryptographicUsageMask` as required by the operation.
    /// Returns `true` if the object can be used, `false` otherwise.
    fn is_key_eligible(owm: &ObjectWithMetadata, vendor_id: &str) -> bool;

    /// Map key-selection errors to operation-specific KMIP error messages.
    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        user: &str,
    ) -> KmsError;

    /// Execute the operation locally using unwrapped key material.
    fn execute_local(
        kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        user: &str,
    ) -> impl std::future::Future<Output = KResult<Self::Response>> + Send;

    /// Execute the operation via a crypto oracle (HSM / external key store).
    fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> impl std::future::Future<Output = KResult<Self::Response>> + Send;
}

/// Generic entry point for all cryptographic operations.
///
/// Resolves the key (oracle or local), enforces algorithm policy,
/// enforces and decrements usage limits, and dispatches to the
/// operation-specific execution logic.
///
/// The clone-before-unwrap pattern ensures wrapped key material is
/// never persisted in plaintext (COSMIAN-2026-015).
pub(crate) async fn perform_crypto_operation<Op: CryptoOpSpec>(
    kms: &KMS,
    request: Op::Request,
    user: &str,
) -> KResult<Op::Response> {
    let unique_identifier =
        Op::unique_identifier(&request).ok_or(KmsError::UnsupportedPlaceholder)?;

    match resolve_key_for_operation::<Op>(unique_identifier, kms, user).await? {
        ResolvedKey::Oracle { uid, prefix } => {
            Op::execute_oracle(kms, &request, &uid, &prefix).await
        }
        ResolvedKey::Local(owm) => {
            let mut owm = *owm;

            // Clone before unwrap: preserve the wrapped key for DB persistence.
            let mut unwrapped_owm = owm.clone();
            unwrap_and_enforce_policy(kms, &mut unwrapped_owm, Op::OP_NAME, user)
                .await
                .with_context(|| {
                    format!(
                        "{}: the key: {}, cannot be unwrapped.",
                        Op::OP_NAME,
                        owm.id()
                    )
                })?;

            let data_len = Op::usage_data_len(&request);
            enforce_usage_limits(&owm, data_len)?;

            let res = Op::execute_local(kms, &unwrapped_owm, &request, user).await?;

            decrement_usage_limits(kms, &mut owm, Op::OP_NAME, data_len).await?;
            Ok(res)
        }
    }
}

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
pub(crate) async fn select_eligible_oracle_uid(
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
            if !kms
                .database
                .is_user_authorized_for_operation(uid, user, operation)
                .await?
            {
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

/// Select exactly one key from a set of candidate UIDs for a cryptographic operation.
///
/// `candidate_uids` is a `HashSet` as returned by `uid_utils::uids_from_unique_identifier`.
/// The function:
///
/// 1. Skips prefix-based (oracle) UIDs — those are handled by the caller before this call.
/// 2. Fetches each object from the database and checks it is `Active` via `get_effective_state`.
/// 3. Verifies the user is authorized via `is_user_authorized_for_operation`.
/// 4. Applies `is_eligible` — a caller-supplied predicate that checks object type / usage mask.
/// 5. Enforces uniqueness: the operation **fails** when more than one eligible key is found.
///    This prevents an attacker from silently substituting a key by tagging a second one.
///
/// # Errors
/// * `KmsError::Unauthorized`   — candidates found but the user has no permission on any of them
/// * `KmsError::ItemNotFound`   — no candidate qualifies after all filters
/// * `KmsError::InvalidRequest` — more than one eligible key matched
pub(crate) async fn select_unique_key_for_operation<F>(
    op_name: &str,
    candidate_uids: &HashSet<String>,
    unique_identifier: &UniqueIdentifier,
    operation: KmipOperation,
    kms: &KMS,
    user: &str,
    is_eligible: F,
) -> KResult<ObjectWithMetadata>
where
    F: Fn(&ObjectWithMetadata) -> KResult<bool>,
{
    let uid_display = unique_identifier.to_string();
    let mut eligible: Vec<ObjectWithMetadata> = Vec::new();
    let mut found_but_no_permission = false;

    for uid in candidate_uids {
        // Oracle (prefix) UIDs are handled by the caller — skip them here.
        if has_prefix(uid).is_some() {
            continue;
        }

        let Some(owm) = kms.database.retrieve_object(uid).await? else {
            continue;
        };

        // Must be Active (respects auto-activation via activation_date).
        if owm.get_effective_state()? != State::Active {
            continue;
        }

        // Permission check via the shared authorization function.
        if !kms
            .database
            .is_user_authorized_for_operation(uid, user, operation)
            .await?
        {
            found_but_no_permission = true;
            continue;
        }

        // Object-type and usage-mask check supplied by the caller.
        if !is_eligible(&owm)? {
            continue;
        }

        eligible.push(owm);
    }

    match eligible.len() {
        1 => eligible
            .into_iter()
            .next()
            .ok_or_else(|| KmsError::ItemNotFound("unreachable: len == 1".to_owned())),
        0 => Err(if found_but_no_permission {
            KmsError::Unauthorized(format!(
                "{op_name}: user {user} does not have permission to use key: {uid_display}"
            ))
        } else {
            KmsError::ItemNotFound(format!(
                "{op_name}: no valid key found for identifier: {uid_display}"
            ))
        }),
        n => {
            let ids: Vec<&str> = eligible.iter().map(ObjectWithMetadata::id).collect();
            Err(KmsError::InvalidRequest(format!(
                "{op_name}: identifier {uid_display} resolves to {n} valid keys {ids:?}; \
                 use a unique identifier"
            )))
        }
    }
}

/// Resolve the key for a cryptographic operation using the [`CryptoOpSpec`] trait.
///
/// Performs the entire key selection pipeline generically:
/// 1. Resolves UIDs from the `unique_identifier`.
/// 2. Attempts oracle (HSM) routing.
/// 3. Selects the key from the database with `Op::is_key_eligible`.
/// 4. Applies error mapping via `Op::map_selection_error`.
/// 5. Enforces process window constraints (`ProcessStartDate` / `ProtectStopDate`).
///
/// Returns [`ResolvedKey::Oracle`] for HSM keys or [`ResolvedKey::Local`] for DB keys.
/// Local keys are NOT unwrapped — `perform_crypto_operation` handles unwrapping.
pub(crate) async fn resolve_key_for_operation<Op: CryptoOpSpec>(
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
    user: &str,
) -> KResult<ResolvedKey> {
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

    // Phase 2 — Standard database path.
    let owm = select_unique_key_for_operation(
        Op::OP_NAME,
        &uids,
        unique_identifier,
        Op::KMIP_OP,
        kms,
        user,
        |owm| Ok(Op::is_key_eligible(owm, kms.vendor_id())),
    )
    .await
    .map_err(|e| Op::map_selection_error(e, unique_identifier, user))?;

    // Lifecycle enforcement: always check process window.
    owm.check_process_window()?;

    Ok(ResolvedKey::Local(Box::new(owm)))
}

/// Unwrap a key (if wrapped) and enforce the KMIP algorithm policy.
///
/// This is the generic second-stage enforcement step shared by all cryptographic
/// operations after key resolution. It:
/// 1. Unwraps the key material (Certificates are never unwrapped).
/// 2. Validates the unwrapped key against the server's configured algorithm policy.
///
/// # Security
///
/// The operation is performed **in-place** on `owm`, replacing the wrapped key material
/// with plaintext.  Callers that later persist `owm` (e.g. via `decrement_usage_limits`)
/// **MUST clone** before calling this function and pass the original (still-wrapped)
/// `owm` to the persistence path.  Failing to do so silently stores the plaintext key
/// in the database, defeating KEK encryption at rest.
pub(crate) async fn unwrap_and_enforce_policy(
    kms: &KMS,
    owm: &mut ObjectWithMetadata,
    op_name: &str,
    user: &str,
) -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object;
    if !matches!(owm.object(), Object::Certificate { .. }) {
        owm.set_object(kms.get_unwrapped(owm.id(), owm.object(), user).await?);
    }
    crate::core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_retrieved_key(
        &kms.params,
        op_name,
        owm.id(),
        owm,
    )
}

// ─── UsageLimits helpers ─────────────────────────────────────────────────────

/// Enforce `UsageLimits` before a cryptographic operation.
///
/// Returns `Err(Permission_Denied / "DENIED")` when the key's remaining usage
/// budget is insufficient for the requested `data_len` bytes.
///
/// For `Byte`-based limits the check is data-length-aware; for `Object`, `Block`,
/// and `Operation` units the limit simply cannot be zero.
pub(crate) fn enforce_usage_limits(owm: &ObjectWithMetadata, data_len: usize) -> KResult<()> {
    let Some(ul) = owm.attributes().usage_limits.as_ref() else {
        return Ok(());
    };
    match ul.usage_limits_unit {
        UsageLimitsUnit::Byte => {
            let needed = i64::try_from(data_len).unwrap_or(i64::MAX);
            if ul.usage_limits_total < needed {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Permission_Denied,
                    "DENIED".to_owned(),
                ));
            }
        }
        UsageLimitsUnit::Object | UsageLimitsUnit::Block | UsageLimitsUnit::Operation => {
            if ul.usage_limits_total <= 0 {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Permission_Denied,
                    "DENIED".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Decrement and persist `UsageLimits` after a successful cryptographic operation.
///
/// For `Byte`-based limits, `data_len` bytes are subtracted from the remaining total.
/// For `Object`, `Block`, and `Operation` units, one unit is consumed.
///
/// Persistence (database UPDATE) is skipped when no usage limits are set on the key,
/// avoiding unnecessary row-level lock contention on the hot path.
pub(crate) async fn decrement_usage_limits(
    kms: &KMS,
    owm: &mut ObjectWithMetadata,
    op_name: &str,
    data_len: usize,
) -> KResult<()> {
    let mut decremented = false;
    if let Some(ref mut ul) = owm.attributes_mut().usage_limits {
        match ul.usage_limits_unit {
            UsageLimitsUnit::Byte => {
                let consumed = i64::try_from(data_len).unwrap_or(i64::MAX);
                ul.usage_limits_total = (ul.usage_limits_total - consumed).max(0);
                decremented = true;
            }
            UsageLimitsUnit::Object | UsageLimitsUnit::Block | UsageLimitsUnit::Operation => {
                ul.usage_limits_total = (ul.usage_limits_total - 1).max(0);
                decremented = true;
            }
        }
    }
    if decremented {
        let attributes = owm.attributes().clone();
        kms.database
            .update_object(owm.id(), owm.object(), &attributes, None)
            .await
            .map_err(|e| {
                KmsError::ServerError(format!(
                    "{op_name}: failed to persist updated usage limits: {e}"
                ))
            })?;
    }
    Ok(())
}
