use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};

use super::{
    authorization::is_user_authorized,
    key_resolution::{KeysetMode, ResolvedKey, resolve_key_for_operation},
    usage_limits::decrement_usage_limits,
};
use crate::{
    core::KMS,
    error::KmsError,
    result::{KResult, KResultHelper},
};

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

    /// How this operation handles a bare keyset name (no `@version` suffix).
    ///
    /// - `SingleLatest`: resolve to the latest key only (encrypt, sign, MAC).
    /// - `TryEach`: walk the chain and try each key newest→oldest (decrypt, verify).
    fn keyset_mode() -> KeysetMode {
        KeysetMode::SingleLatest
    }

    /// Compute the data length for `UsageLimits` enforcement.
    ///
    /// The meaning varies per operation:
    /// - Encrypt: plaintext length
    /// - Decrypt: ciphertext length
    /// - Sign/SignatureVerify: max(data, `digested_data`) length
    /// - MAC/MACVerify: data length
    fn usage_data_len(request: &Self::Request) -> usize;

    /// Key states accepted by this operation.
    ///
    /// Per KMIP 2.1 §3.31:
    /// - Protection operations (Encrypt, Sign, MAC) require `Active` only.
    /// - Processing operations (Decrypt, Verify, `MACVerify`) accept `Active`,
    ///   `Deactivated`, and `Compromised` — because deactivated/compromised keys
    ///   must remain usable to process previously protected data.
    ///
    /// Default: `&[State::Active]` — override for processing operations.
    fn accepted_states() -> &'static [State] {
        &[State::Active]
    }

    /// Determine if the given managed object is eligible for this operation.
    ///
    /// Checks object type and `CryptographicUsageMask` as required by the operation.
    /// Returns `true` if the object can be used, `false` otherwise.
    fn is_key_eligible(owm: &ObjectWithMetadata, vendor_id: &str) -> bool;

    /// Map key-selection errors to operation-specific KMIP error messages.
    ///
    /// Default implementation collapses `ItemNotFound` and `Unauthorized` into a
    /// single `Kmip21Error(Item_Not_Found, ...)`. Operations that need distinct
    /// error variants (e.g. Encrypt, Decrypt) override this.
    fn map_selection_error(
        e: KmsError,
        unique_identifier: &UniqueIdentifier,
        _user: &str,
    ) -> KmsError {
        match e {
            KmsError::ItemNotFound(_) | KmsError::Unauthorized(_) => KmsError::Kmip21Error(
                ErrorReason::Item_Not_Found,
                format!(
                    "{}: no valid key for id: {unique_identifier}",
                    Self::OP_NAME
                ),
            ),
            other => other,
        }
    }

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
            let result = Op::execute_oracle(kms, &request, &uid, &prefix).await?;
            if let Some(ref metrics) = kms.metrics {
                let model = crate::core::uid_utils::hsm_model_from_prefix(
                    &kms.params.hsm_instances,
                    &prefix,
                );
                metrics.record_hsm_operation(Op::OP_NAME, model);
            }
            Ok(result)
        }
        ResolvedKey::Local(owm) => execute_local_with_limits::<Op>(kms, *owm, &request, user).await,
        ResolvedKey::Keyset(chain) => {
            execute_keyset_try_each::<Op>(kms, &chain, &request, user).await
        }
    }
}

/// Execute a local operation with unwrapping and usage-limit accounting.
async fn execute_local_with_limits<Op: CryptoOpSpec>(
    kms: &KMS,
    owm: ObjectWithMetadata,
    request: &Op::Request,
    user: &str,
) -> KResult<Op::Response> {
    let mut owm = owm;

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

    let data_len = Op::usage_data_len(request);
    owm.enforce_usage_limits(data_len)?;

    let res = Op::execute_local(kms, &unwrapped_owm, request, user).await?;

    decrement_usage_limits(kms, &mut owm, Op::OP_NAME, data_len).await?;
    Ok(res)
}

/// Try each key in a keyset chain (newest→oldest) until one succeeds.
///
/// The traversal is unbounded: `walk_keyset_chain` already guarantees termination
/// via cycle detection.  A server-side warning is emitted whenever the depth is
/// ≥ `params.keyset_warn_depth`.
async fn execute_keyset_try_each<Op: CryptoOpSpec>(
    kms: &KMS,
    chain: &[String],
    request: &Op::Request,
    user: &str,
) -> KResult<Op::Response> {
    let mut last_err: Option<KmsError> = None;

    for (depth, uid) in chain.iter().enumerate() {
        let Some(owm) = kms.database.retrieve_object(uid).await? else {
            continue;
        };

        // State filter: per KMIP 2.1 §3.31, processing operations (Decrypt, Verify)
        // accept Deactivated/Compromised keys; protection operations require Active only.
        if !Op::accepted_states().contains(&owm.effective_state()) {
            continue;
        }

        // Permission check
        if !is_user_authorized(&kms.database, uid, user, Op::KMIP_OP).await? {
            continue;
        }

        // Eligibility check
        if !Op::is_key_eligible(&owm, kms.vendor_id()) {
            continue;
        }

        // Lifecycle check
        if owm.check_process_window().is_err() {
            continue;
        }

        match execute_local_with_limits::<Op>(kms, owm, request, user).await {
            Ok(response) => {
                let depth_u32 = u32::try_from(depth).unwrap_or(u32::MAX);
                let warn_threshold = kms.params.keyset_warn_depth;
                if depth_u32 >= warn_threshold {
                    warn!(
                        "{}: keyset chain depth {} ≥ warn threshold {} for uid {}; \
                         consider re-encrypting with the latest key",
                        Op::OP_NAME,
                        depth_u32,
                        warn_threshold,
                        uid
                    );
                }
                return Ok(response);
            }
            Err(e) => {
                trace!(
                    "execute_keyset_try_each: key {} failed for {}: {}",
                    uid,
                    Op::OP_NAME,
                    e
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!(
                "{}: decryption failed — no key in the keyset could process the request",
                Op::OP_NAME
            ),
        )
    }))
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
async fn unwrap_and_enforce_policy(
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
