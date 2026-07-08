//! KMIP cryptographic operation dispatch: key resolution, execution,
//! lifecycle enforcement, and usage-limit accounting.
//!
//! This module owns:
//! - [`CryptoOpSpec`] — operation-specific trait for crypto operations.

//! - [`KeySelectionSpec`] — generic key-selection spec shared with rekey operations.
//! - [`KeysetMode`] — how a bare keyset name is handled.
//! - [`perform_crypto_operation`] — generic entry point for all crypto ops.
//! - [`select_unique_key`] — single-candidate selection helper (also used by rekey).
//! - [`setup_object_lifecycle`] — lifecycle initialization for newly created objects.
//!
//! ## Key resolution pipeline
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
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Object, ObjectType},
            kmip_types::{UniqueIdentifier, UsageLimitsUnit},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS,
        operations::{
            algorithm_policy::enforce_kmip_algorithm_policy_for_retrieved_key, digest::digest,
        },
        uid_utils::{
            KeysetVersion, has_prefix, parse_keyset_identifier, resolve_keyset_to_single_uid,
            uids_from_unique_identifier, walk_keyset_chain,
        },
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

// ─── Key lifecycle initialization ─────────────────────────────────────────────

/// Extension trait on [`Object`] for server-side lifecycle initialization.
///
/// This trait bridges the KMIP crate's [`Object::setup_lifecycle`] with the
/// server-crate-specific [`digest`] function (which requires OpenSSL). The
/// kmip crate has no OpenSSL dependency so the digest computation lives here.
pub(crate) trait ObjectLifecycleExt {
    /// Initialize lifecycle attributes on this newly created or imported object.
    ///
    /// Computes the KMIP digest (SHA-256 via OpenSSL), then delegates to
    /// [`Object::setup_lifecycle`] for the state-machine logic.
    fn setup_with_lifecycle(
        &mut self,
        object_type: ObjectType,
        requested_activation_date: Option<OffsetDateTime>,
    ) -> KResult<Attributes>;
}

impl ObjectLifecycleExt for Object {
    fn setup_with_lifecycle(
        &mut self,
        object_type: ObjectType,
        requested_activation_date: Option<OffsetDateTime>,
    ) -> KResult<Attributes> {
        let computed_digest = digest(self)?;
        Ok(self.setup_lifecycle(object_type, requested_activation_date, computed_digest)?)
    }
}

// ─── Keyset mode ──────────────────────────────────────────────────────────────

/// Determines how a keyset reference (bare name without `@version`) is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysetMode {
    /// Use only the latest key in the keyset (for encrypt, sign, MAC).
    SingleLatest,
    /// Try each key in the chain from newest to oldest (for decrypt, verify).
    TryEach,
}

// ─── Key selection trait ──────────────────────────────────────────────────────

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

// ─── Crypto operation specification ───────────────────────────────────────────

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

// ─── Generic key selection ────────────────────────────────────────────────────

/// Result of key resolution for a cryptographic operation.
enum ResolvedKey {
    /// Key lives on an external crypto oracle (HSM / external key store).
    Oracle { uid: String, prefix: String },
    /// Key is in the local database: selected, Active, lifecycle-validated.
    /// NOT yet unwrapped — `perform_crypto_operation` handles unwrapping.
    Local(Box<ObjectWithMetadata>),
    /// A keyset chain: ordered list of UIDs from newest to oldest.
    Keyset(Vec<String>),
}

impl KMS {
    /// Select exactly one key from pre-fetched candidates using the [`KeySelectionSpec`] pipeline.
    ///
    /// Applies the following filters in order:
    /// 1. **State** — `Spec::accepted_states()`
    /// 2. **Permission** — ownership or explicit grant, optionally with `Get` wildcard
    /// 3. **Eligibility** — `Spec::is_key_eligible()`
    /// 4. **Extra validation** — caller-supplied closure for operation-specific checks
    ///    (e.g. keyset-latest guard, crypto-param change rejection)
    ///
    /// Enforces uniqueness:
    /// - 0 eligible → `KmsError::ItemNotFound` or `KmsError::Unauthorized`
    /// - 1 eligible → `Ok(ObjectWithMetadata)`
    /// - \>1 eligible → `KmsError::InvalidRequest` (ambiguous)
    pub(crate) async fn select_unique_key<Spec, F>(
        &self,
        candidates: Vec<ObjectWithMetadata>,
        uid_display: &str,
        user: &str,
        extra_validation: F,
    ) -> KResult<ObjectWithMetadata>
    where
        Spec: KeySelectionSpec,
        F: Fn(&ObjectWithMetadata) -> KResult<()>,
    {
        let mut eligible: Vec<ObjectWithMetadata> = Vec::new();
        let mut found_but_no_permission = false;
        // Track state mismatches so we can surface a useful error instead of "not found".
        let mut wrong_state: Option<(String, State)> = None;

        for owm in candidates {
            // 1. State filter
            let effective = owm.effective_state();
            if !Spec::accepted_states().contains(&effective) {
                // Track live-but-wrong-state for a useful error message.
                // Skip Destroyed/DestroyedCompromised: those behave as "not found".
                if effective != State::Destroyed && effective != State::Destroyed_Compromised {
                    wrong_state.get_or_insert_with(|| (owm.id().to_owned(), effective));
                }
                continue;
            }

            // 2. Permission check
            let authorized = if Spec::strict_permission_check() {
                // Strict: only exact operation grant (no Get wildcard)
                self.user_can_perform_operation(&owm, user, &Spec::KMIP_OP)
                    .await?
            } else {
                // Lenient: Get grant also authorizes (standard for crypto ops)
                self.is_user_authorized_with_get_wildcard(owm.id(), user, Spec::KMIP_OP)
                    .await?
            };
            if !authorized {
                found_but_no_permission = true;
                continue;
            }

            // 3. Eligibility (object type + usage mask)
            if !Spec::is_key_eligible(&owm, self.vendor_id()) {
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
            } else if let Some((uid, state)) = wrong_state {
                KmsError::Kmip21Error(
                    ErrorReason::Permission_Denied,
                    format!(
                        "{}: key {uid} is in state {state:?} but operation requires one of {:?}",
                        Spec::OP_NAME,
                        Spec::accepted_states()
                    ),
                )
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

    /// Generic entry point for all cryptographic operations.
    ///
    /// Resolves the key (oracle or local), enforces algorithm policy,
    /// enforces and decrements usage limits, and dispatches to the
    /// operation-specific execution logic.
    ///
    /// The clone-before-unwrap pattern ensures wrapped key material is
    /// never persisted in plaintext (COSMIAN-2026-015).
    pub(crate) async fn perform_crypto_operation<Op: CryptoOpSpec>(
        &self,
        request: Op::Request,
        user: &str,
    ) -> KResult<Op::Response> {
        let unique_identifier =
            Op::unique_identifier(&request).ok_or(KmsError::UnsupportedPlaceholder)?;

        match self
            .resolve_key_for_operation::<Op>(unique_identifier, user)
            .await?
        {
            ResolvedKey::Oracle { uid, prefix } => {
                let result = Op::execute_oracle(self, &request, &uid, &prefix).await?;
                if let Some(ref metrics) = self.metrics {
                    let model = crate::core::uid_utils::hsm_model_from_prefix(
                        &self.params.hsm_instances,
                        &prefix,
                    );
                    metrics.record_hsm_operation(Op::OP_NAME, model);
                }
                Ok(result)
            }
            ResolvedKey::Local(owm) => {
                self.execute_local_with_limits::<Op>(&owm, &request, user)
                    .await
            }
            ResolvedKey::Keyset(chain) => {
                self.execute_keyset_try_each::<Op>(&chain, &request, user)
                    .await
            }
        }
    }

    /// Execute a local operation with unwrapping and usage-limit accounting.
    ///
    /// `owm` is taken by mutable reference rather than by value: both call sites
    /// already own the object and don't need it afterward, so operating in place
    /// avoids moving the (comparatively large) `ObjectWithMetadata` struct -- `id`,
    /// `owner`, the `Object` enum, and the `Attributes` struct -- onto this
    /// function's stack frame on every cryptographic operation.
    async fn execute_local_with_limits<Op: CryptoOpSpec>(
        &self,
        owm: &ObjectWithMetadata,
        request: &Op::Request,
        user: &str,
    ) -> KResult<Op::Response> {
        let data_len = Op::usage_data_len(request);

        // Algorithm policy enforcement only inspects `KeyBlock`/`Attributes` metadata
        // (algorithm, length, curve), which is identical whether the key is wrapped or
        // not, so it can run once on `owm`, before any unwrapping takes place.
        enforce_kmip_algorithm_policy_for_retrieved_key(&self.params, Op::OP_NAME, owm.id(), owm)?;
        owm.enforce_usage_limits(data_len)?;

        // The clone is only needed when the key is wrapped: unwrapping mutates the
        // object, replacing the wrapped key material with plaintext.
        // `decrement_usage_limits` below persists `owm.object()` back to the database,
        // so unwrapping `owm` directly would leak the plaintext key to storage
        // (COSMIAN-2026-015). Only the disposable `unwrapped_owm` clone may ever hold
        // plaintext key material -- `owm` must remain wrapped for persistence.
        //
        // `enforce_usage_limits`/`decrement_usage_limits` are no-ops when the key has
        // no `UsageLimits` set, so they are called unconditionally rather than gating
        // the fast path on that as well.
        // Clone for crypto use: this clone may be unwrapped to obtain plaintext
        // key material needed by the algorithm.  The original `owm` keeps its
        // wrapped key material, which is passed directly to `decrement_usage_limits`
        // for persistence — no second clone needed (COSMIAN-2026-015).
        let mut local_owm = owm.clone();
        if local_owm.object().is_wrapped() {
            let unwrapped = Box::pin(self.get_unwrapped(local_owm.id(), local_owm.object(), user))
                .await
                .with_context(|| {
                    format!(
                        "{}: the key: {}, cannot be unwrapped.",
                        Op::OP_NAME,
                        owm.id()
                    )
                })?;
            local_owm.set_object(unwrapped);
        }

        let res = Op::execute_local(self, &local_owm, request, user).await?;

        // Persist usage limits: `owm.object()` is still wrapped, avoiding
        // plaintext leakage; `local_owm.attributes_mut()` has the decremented
        // counter computed right here.
        self.decrement_usage_limits(
            owm.id(),
            owm.object(),
            local_owm.attributes_mut(),
            Op::OP_NAME,
            data_len,
        )
        .await?;
        Ok(res)
    }

    /// Try each key in a keyset chain (newest→oldest) until one succeeds.
    ///
    /// The traversal is unbounded: `walk_keyset_chain` already guarantees termination
    /// via cycle detection.  A server-side warning is emitted whenever the depth is
    /// ≥ `params.keyset_warn_depth`.
    async fn execute_keyset_try_each<Op: CryptoOpSpec>(
        &self,
        chain: &[String],
        request: &Op::Request,
        user: &str,
    ) -> KResult<Op::Response> {
        let mut last_err: Option<KmsError> = None;

        for (depth, uid) in chain.iter().enumerate() {
            let Some(owm) = self.database.retrieve_object(uid).await? else {
                continue;
            };

            // State filter: per KMIP 2.1 §3.31, processing operations (Decrypt, Verify)
            // accept Deactivated/Compromised keys; protection operations require Active only.
            if !Op::accepted_states().contains(&owm.effective_state()) {
                continue;
            }

            // Permission check
            if !self
                .is_user_authorized_with_get_wildcard(uid, user, Op::KMIP_OP)
                .await?
            {
                continue;
            }

            // Eligibility check
            if !Op::is_key_eligible(&owm, self.vendor_id()) {
                continue;
            }

            // Lifecycle check
            if owm.check_process_window().is_err() {
                continue;
            }

            match self
                .execute_local_with_limits::<Op>(&owm, request, user)
                .await
            {
                Ok(response) => {
                    let depth_u32 = u32::try_from(depth).unwrap_or(u32::MAX);
                    let warn_threshold = self.params.keyset_warn_depth;
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

    /// Check whether a user is authorized to perform `operation` on the object
    /// identified by `uid`, with `Get` wildcard for non-HSM keys.
    ///
    /// The user is authorized if they own the object, or have been granted the
    /// specific `operation` **or** `Get` (which implies read-level access).
    /// For HSM keys (prefix-based UIDs), the `Get` wildcard is **not** applied.
    pub(crate) async fn is_user_authorized_with_get_wildcard(
        &self,
        uid: &str,
        user: &str,
        operation: KmipOperation,
    ) -> KResult<bool> {
        if self.database.is_object_owned_by(uid, user).await? {
            return Ok(true);
        }
        let ops = self
            .database
            .list_user_operations_on_object(uid, user, false)
            .await?;

        // HSM keys: each operation must be explicitly granted — no Get wildcard
        if has_prefix(uid).is_some() {
            return Ok(ops.iter().any(|p| *p == operation));
        }

        Ok(ops
            .iter()
            .any(|p| *p == operation || *p == KmipOperation::Get))
    }

    /// Decrement and persist `UsageLimits` after a successful cryptographic operation.
    ///
    /// For `Byte`-based limits, `data_len` bytes are subtracted from the remaining total.
    /// For `Object`, `Block`, and `Operation` units, one unit is consumed.
    ///
    /// Persistence is skipped when no usage limits are set on the key,
    /// avoiding unnecessary row-level lock contention on the hot path.
    /// Decrement the `UsageLimits` counter on `attributes` and persist the original
    /// `object` together with the updated attributes to the database.
    ///
    /// The `object` and `attributes` are split so the caller can pass the
    /// original (still-wrapped) key material alongside the decremented
    /// attributes from a disposable clone — this avoids a full second clone
    /// just for persistence (COSMIAN-2026-015).
    async fn decrement_usage_limits(
        &self,
        id: &str,
        object: &Object,
        attributes: &mut Attributes,
        op_name: &str,
        data_len: usize,
    ) -> KResult<()> {
        let mut decremented = false;
        if let Some(ul) = attributes.usage_limits.as_mut() {
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
            self.database
                .update_object(id, object, attributes, None)
                .await
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "{op_name}: failed to persist updated usage limits: {e}"
                    ))
                })?;
        }
        Ok(())
    }

    /// Collect the single eligible crypto-oracle UID for a cryptographic operation.
    ///
    /// Returns `Ok(None)` if no oracle UID is eligible, `Ok(Some((uid, prefix)))` for
    /// exactly one, or `Err(InvalidRequest)` when multiple are ambiguously eligible.
    async fn select_eligible_oracle_uid(
        &self,
        operation: KmipOperation,
        op_name: &str,
        candidate_uids: &HashSet<String>,
        unique_identifier: &UniqueIdentifier,
        user: &str,
    ) -> KResult<Option<(String, String)>> {
        let mut eligible: Vec<(String, String)> = Vec::new();
        for uid in candidate_uids {
            if let Some(prefix) = has_prefix(uid) {
                if !self
                    .is_user_authorized_with_get_wildcard(uid, user, operation)
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

    /// Resolve the key for a cryptographic operation using the [`CryptoOpSpec`] trait.
    ///
    /// Performs the entire key selection pipeline:
    /// 1. Keyset detection (name or name@version).
    /// 2. Standard UID / tag resolution.
    /// 3. Oracle (HSM) routing.
    /// 4. Database selection with `Op::is_key_eligible` + uniqueness enforcement.
    /// 5. Error mapping via `Op::map_selection_error`.
    /// 6. Process window enforcement (`ProcessStartDate` / `ProtectStopDate`).
    async fn resolve_key_for_operation<Op: CryptoOpSpec>(
        &self,
        unique_identifier: &UniqueIdentifier,
        user: &str,
    ) -> KResult<ResolvedKey> {
        let uid_str = unique_identifier
            .as_str()
            .context("The unique identifier must be a string")?;

        // ── Keyset detection ─────────────────────────────────────────────────────
        if let Some(keyset_ref) = parse_keyset_identifier(uid_str) {
            match &keyset_ref.version {
                KeysetVersion::Latest | KeysetVersion::First | KeysetVersion::Generation(_) => {
                    if let Some(uid) = resolve_keyset_to_single_uid(&keyset_ref, self, user).await?
                    {
                        let owm = self.database.retrieve_object(&uid).await?.ok_or_else(|| {
                            KmsError::ItemNotFound(format!(
                                "{}: keyset key not found: {uid}",
                                Op::OP_NAME
                            ))
                        })?;
                        owm.check_process_window()?;
                        // KMIP §4.57: enforce state requirements for keyset-addressed keys
                        let effective = owm.effective_state();
                        if !Op::accepted_states().contains(&effective) {
                            return Err(KmsError::Kmip21Error(
                                ErrorReason::Permission_Denied,
                                format!(
                                    "{}: key {uid} is in state {effective:?} but operation \
                                     requires one of {:?}",
                                    Op::OP_NAME,
                                    Op::accepted_states()
                                ),
                            ));
                        }
                        return Ok(ResolvedKey::Local(Box::new(owm)));
                    }
                    // Not a keyset → fall through to normal UID resolution
                }
                KeysetVersion::Bare => match Op::keyset_mode() {
                    KeysetMode::SingleLatest => {
                        if let Some(uid) =
                            resolve_keyset_to_single_uid(&keyset_ref, self, user).await?
                        {
                            let owm =
                                self.database.retrieve_object(&uid).await?.ok_or_else(|| {
                                    KmsError::ItemNotFound(format!(
                                        "{}: keyset key not found: {uid}",
                                        Op::OP_NAME
                                    ))
                                })?;
                            owm.check_process_window()?;
                            // KMIP §4.57: enforce state requirements for keyset-addressed keys
                            let effective = owm.effective_state();
                            if !Op::accepted_states().contains(&effective) {
                                return Err(KmsError::Kmip21Error(
                                    ErrorReason::Permission_Denied,
                                    format!(
                                        "{}: key {uid} is in state {effective:?} but operation \
                                         requires one of {:?}",
                                        Op::OP_NAME,
                                        Op::accepted_states()
                                    ),
                                ));
                            }
                            return Ok(ResolvedKey::Local(Box::new(owm)));
                        }
                        // Not a keyset → fall through to normal path
                    }
                    KeysetMode::TryEach => {
                        let chain = walk_keyset_chain(&keyset_ref.name, self, user).await?;
                        if !chain.is_empty() {
                            return Ok(ResolvedKey::Keyset(chain));
                        }
                        // Not a keyset → fall through to normal path
                    }
                },
            }
        }

        // ── Standard UID / tag resolution ────────────────────────────────────────
        let uids = uids_from_unique_identifier(unique_identifier, self)
            .await
            .context(Op::OP_NAME)?;

        // Phase 1 — Oracle (HSM / prefix) routing.
        if let Some((uid, prefix)) = self
            .select_eligible_oracle_uid(Op::KMIP_OP, Op::OP_NAME, &uids, unique_identifier, user)
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
            if let Some(owm) = self.database.retrieve_object(uid).await? {
                candidates.push(owm);
            }
        }
        let uid_display = unique_identifier.to_string();
        let owm = self
            .select_unique_key::<Op, _>(candidates, &uid_display, user, |_| Ok(()))
            .await
            .map_err(|e| Op::map_selection_error(e, unique_identifier, user))?;

        // Lifecycle enforcement: always check process window.
        owm.check_process_window()?;

        Ok(ResolvedKey::Local(Box::new(owm)))
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)]
mod tests {
    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::State,
            kmip_2_1::{
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
                kmip_objects::{Object, ObjectType, SymmetricKey},
                kmip_types::{CryptographicAlgorithm, KeyFormatType},
            },
            time_normalize,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    };
    use time::Duration;
    use zeroize::Zeroizing;

    use super::ObjectLifecycleExt;
    use crate::result::KResult;

    fn test_object() -> Object {
        Object::SymmetricKey(SymmetricKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::new(vec![1, 2, 3, 4])),
                    attributes: Some(Attributes::default()),
                }),
                key_compression_type: None,
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                key_wrapping_data: None,
            },
        })
    }

    #[test]
    fn test_effective_state_preactive_with_past_activation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::PreActive),
            activation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Active);
        Ok(())
    }

    #[test]
    fn test_effective_state_preactive_with_future_activation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::PreActive),
            activation_date: Some(time_normalize()? + Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::PreActive);
        Ok(())
    }

    #[test]
    fn test_effective_state_preactive_without_activation_date() {
        let attrs = Attributes {
            state: Some(State::PreActive),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::PreActive);
    }

    #[test]
    fn test_setup_object_lifecycle_past_date_gives_active() -> KResult<()> {
        let mut obj = test_object();
        let past = time_normalize()? - Duration::hours(1);
        let attrs = obj.setup_with_lifecycle(ObjectType::SymmetricKey, Some(past))?;
        assert_eq!(attrs.state, Some(State::Active));
        Ok(())
    }

    #[test]
    fn test_setup_object_lifecycle_no_date_gives_preactive() -> KResult<()> {
        let mut obj = test_object();
        let attrs = obj.setup_with_lifecycle(ObjectType::SymmetricKey, None)?;
        assert_eq!(attrs.state, Some(State::PreActive));
        Ok(())
    }

    #[test]
    fn test_setup_object_lifecycle_future_date_gives_preactive() -> KResult<()> {
        let mut obj = test_object();
        let future = time_normalize()? + Duration::hours(1);
        let attrs = obj.setup_with_lifecycle(ObjectType::SymmetricKey, Some(future))?;
        assert_eq!(attrs.state, Some(State::PreActive));
        assert_eq!(attrs.activation_date, Some(future));
        Ok(())
    }

    #[test]
    fn test_effective_state_active_remains_active() {
        let attrs = Attributes {
            state: Some(State::Active),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Active);
    }

    #[test]
    fn test_effective_state_active_with_past_deactivation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::Active),
            deactivation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Deactivated);
        Ok(())
    }

    #[test]
    fn test_effective_state_active_with_future_deactivation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::Active),
            deactivation_date: Some(time_normalize()? + Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Active);
        Ok(())
    }
}
