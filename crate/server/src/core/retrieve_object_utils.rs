use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{KmipOperation, kmip_attributes::Attributes},
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS,
        opa::{OpaClient, OpaInput, OpaMode, get_opa_user_context},
        uid_utils::ObjectHandle,
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

// TODO This function should probably not be a free-standing function KMS side,
// and should be refactored as part of the Database,

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// When tags are provided, the function will return the first object
/// that matches the tags and the operation type.
///
/// This function assumes that if the user can `Get` the object,
/// it can then also perform any other operation with it.
///
/// A due time-based lifecycle transition (KMIP 2.1 §4.57) is persisted first; the returned
/// object is then a fresh store snapshot whose state and version match that write.
pub(crate) async fn retrieve_object_for_operation(
    object_handle: ObjectHandle<'_>,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> KResult<Arc<ObjectWithMetadata>> {
    trace!(
        "object_handle: {object_handle}, user: {user}, \
         operation_type: {operation_type:?}",
    );

    let mut candidates = kms
        .database
        .retrieve_objects(object_handle)
        .await?
        .into_values();
    // A snapshot re-read after persisting an automatic lifecycle transition is re-validated next.
    let mut refreshed_owm: Option<Arc<ObjectWithMetadata>> = None;
    while let Some((mut owm, refreshed)) = refreshed_owm
        .take()
        .map(|owm| (owm, true))
        .or_else(|| candidates.next().map(|owm| (owm, false)))
    {
        trace!("Checking key with ID: {}", owm.id());
        let state = owm.state();
        // Allow retrieval based on state and operation semantics.
        // Rules:
        // - Active / PreActive: always retrievable.
        // - Compromised: permitted for Get / Export / GetAttributes (profiling vectors inspect attrs post-revoke).
        // - Destroyed / Destroyed_Compromised: ONLY permit GetAttributes so clients can read lifecycle state.
        let state_allows = match state {
            State::Active | State::PreActive | State::Deactivated => true,
            State::Compromised => matches!(
                operation_type,
                KmipOperation::Get
                    | KmipOperation::Export
                    | KmipOperation::GetAttributes
                    // Attribute operations do not expose key material; KMIP allows
                    // adding/modifying/deleting attributes on compromised objects
                    // (SKFF-M-9 test vectors exercise exactly this flow).
                    | KmipOperation::AddAttribute
                    | KmipOperation::ModifyAttribute
                    | KmipOperation::SetAttribute
                    | KmipOperation::DeleteAttribute
                    // Activate on a compromised key must return Wrong_Key_Lifecycle_State
                    // ("cannot be activated") rather than Object_Not_Found; allow retrieval
                    // so activate.rs can emit the correct lifecycle error.
                    | KmipOperation::Activate
                    // Validate reports a revoked certificate as Invalid (KMIP 2.1 §6.1.58)
                    | KmipOperation::Validate
            ),
            State::Destroyed | State::Destroyed_Compromised => {
                // KMIP profiles expect Get on a destroyed object to return OperationFailed / ObjectDestroyed
                // rather than ObjectNotFound. We therefore allow retrieval for Get so the operation layer
                // can emit the correct Object_Destroyed error (BL-M-8-21 vector). Still restrict other
                // operations besides GetAttributes and Get.
                // Similarly, Activate on a destroyed object must return Wrong_Key_Lifecycle_State
                // ("cannot be activated") rather than Object_Not_Found; allow retrieval so activate.rs
                // can emit the correct lifecycle error.
                // Export of a destroyed object succeeds without key material (KMIP 2.1 §6.1.18).
                matches!(
                    operation_type,
                    KmipOperation::Get
                        | KmipOperation::Export
                        | KmipOperation::GetAttributes
                        | KmipOperation::Activate
                        | KmipOperation::Validate
                )
            }
        };
        if !state_allows {
            trace!(
                "state_allows: {state_allows}: state: {state}, operation_type: {operation_type}"
            );
            continue;
        }

        if user_has_permission(user, Some(owm.as_ref()), &operation_type, kms).await? {
            trace!(
                "User {user} has permission for operation {operation_type:?} on object {}",
                owm.id()
            );
            // Compute effective state with lifecycle precedence:
            // - If the DB marks the object as Destroyed / Destroyed_Compromised / Compromised / Deactivated,
            //   NEVER override it with attribute-level values.
            // - Otherwise (Active/PreActive), prefer attribute PreActive when present to satisfy
            //   profile vectors that keep objects PreActive until explicit Activate.
            let attr_state = owm.attributes().state;
            let effective_state = match state {
                State::Destroyed
                | State::Destroyed_Compromised
                | State::Compromised
                | State::Deactivated
                | State::Active => state, // never downgrade Active to PreActive
                State::PreActive => attr_state.unwrap_or(State::PreActive),
            };
            // Synchronize both external attributes and embedded object attributes to effective state.
            // Only copy-on-write when something actually differs (cached objects are shared).
            let embedded_differs = owm
                .object()
                .attributes()
                .is_ok_and(|attributes| attributes.state != Some(effective_state));
            if owm.attributes().state != Some(effective_state) || embedded_differs {
                let owm = Arc::make_mut(&mut owm);
                owm.attributes_mut().state = Some(effective_state);
                if let Ok(attributes) = owm.object_mut().attributes_mut() {
                    attributes.state = Some(effective_state);
                }
            }

            // KMIP 2.1 §4.57 time-based transitions. A refreshed snapshot already carries the
            // transition persisted on its first pass, so it is never transitioned again.
            // Activate performs PreActive → Active itself and must still see PreActive.
            if !refreshed
                && operation_type != KmipOperation::Activate
                && let Some(target) = due_lifecycle_transition(&owm, effective_state)?
            {
                trace!(
                    "Auto-transitioning object {} from {effective_state} to {target}",
                    owm.id()
                );
                match kms.database.update_state(owm.id(), target).await {
                    // `update_state` bumped the stored version: re-read a coherent snapshot
                    // (state, attributes, version) so a caller's optimistic lock matches the
                    // store, and re-validate it from the top. Gone meanwhile → not found.
                    Ok(()) => {
                        refreshed_owm = kms.database.retrieve_object_arc(owm.id()).await?;
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to persist automatic transition of object {} to {target}: {e}",
                            owm.id()
                        );
                        let owm_mut = Arc::make_mut(&mut owm);
                        owm_mut.attributes_mut().state = Some(target);
                        if let Ok(attributes) = owm_mut.object_mut().attributes_mut() {
                            attributes.state = Some(target);
                        }
                    }
                }
            }

            // Automatic object unwrapping (if object type is not filtered)
            // Skip unwrapping for destroyed objects as they have empty key material
            // Skip unwrapping for attribute-only operations to prevent persisting the
            // unwrapped key back to the database when the caller later calls update_object
            // (e.g. ModifyAttribute, SetAttribute, AddAttribute, DeleteAttribute, Activate).
            // Operations that need the key material (Get, Export) handle unwrapping
            // themselves in export_get.rs.
            let skip_unwrap = matches!(
                operation_type,
                KmipOperation::GetAttributes
                    | KmipOperation::SetAttribute
                    | KmipOperation::ModifyAttribute
                    | KmipOperation::AddAttribute
                    | KmipOperation::DeleteAttribute
                    | KmipOperation::Activate
            );
            if !skip_unwrap
                && let Some(defaults) = &kms.params.default_unwrap_types
                && defaults.contains(&owm.object().object_type())
                && state != State::Destroyed
                && state != State::Destroyed_Compromised
            {
                let unwrapped_object =
                    Box::pin(kms.get_unwrapped(owm.id(), owm.object(), user)).await?;
                Arc::make_mut(&mut owm).set_object(unwrapped_object);
            }

            return Ok(owm);
        }
        trace!(
            "User {user} does not have permission for operation {operation_type:?} on object {}",
            owm.id()
        );
    }

    Err(KmsError::Kmip21Error(
        ErrorReason::Object_Not_Found,
        format!("object not found for identifier {object_handle}"),
    ))
}

/// Build the OPA input document from the current request context.
///
/// Fields that require the authentication server integration (roles, `user_domain`)
/// are populated from the JWT claims extracted by the middleware.
fn build_opa_input(
    user: &str,
    roles: &[String],
    user_domain: Option<&str>,
    owm: Option<&ObjectWithMetadata>,
    operation_type: KmipOperation,
) -> OpaInput {
    let (object_uid, object_domain, is_owner) = owm.map_or_else(
        || {
            (
                // Object-less operations (Create, Locate, …): use wildcard UID and derive the
                // object domain from the caller's domain so that the `same_domain` rule passes
                // for a caller that has a domain (an empty domain never matches).
                "*".to_owned(),
                user_domain.unwrap_or_default().to_owned(),
                false,
            )
        },
        |obj| {
            (
                obj.id().to_owned(),
                obj.domain().to_owned(),
                user == obj.owner(),
            )
        },
    );

    OpaInput {
        user: user.to_owned(),
        user_domain: user_domain.unwrap_or_default().to_owned(),
        roles: roles.to_vec(),
        operation: operation_type.to_string(),
        object_uid,
        object_domain,
        is_owner,
    }
}

/// Ask OPA whether `user` may perform `operation_type` on `owm`, and record a denial.
///
/// Fail-closed: a transport or parsing error counts as a denial (the client has already
/// logged the cause). Every denial is written to the `audit` target, with the identity, roles,
/// domains, operation and object, so that blocked access attempts and an unavailable policy
/// engine can be alerted on. The claim-derived values use `Debug` formatting so that control
/// characters cannot forge log lines.
async fn opa_decision(
    opa_client: &OpaClient,
    mode: OpaMode,
    user: &UserId,
    owm: Option<&ObjectWithMetadata>,
    operation_type: KmipOperation,
) -> bool {
    let opa_ctx = get_opa_user_context();
    let input = build_opa_input(
        user,
        &opa_ctx.roles,
        opa_ctx.domain.as_deref(),
        owm,
        operation_type,
    );
    let allowed = opa_client.query(&input).await.unwrap_or(false);
    if allowed {
        trace!(
            "OPA {mode} decision for user={:?} op={} obj={:?}: allowed",
            input.user, input.operation, input.object_uid
        );
    } else {
        warn!(
            target: "audit",
            user = ?input.user,
            roles = ?input.roles,
            user_domain = ?input.user_domain,
            operation = %input.operation,
            object_id = ?input.object_uid,
            object_domain = ?input.object_domain,
            mode = %mode,
            "OPA_DENIED: request denied by the OPA policy, or OPA was unavailable (fail-closed)",
        );
    }
    allowed
}

/// KMIP 2.1 §4.57 time-based transition due on an object in `state`: `PreActive` → Active once
/// its Activation Date has passed (transition 4), chained with Active → Deactivated once its
/// Deactivation Date has passed (transition 6). Dates come from the external attributes, then
/// from the embedded object attributes. Returns the target state, if it differs from `state`.
fn due_lifecycle_transition(owm: &ObjectWithMetadata, state: State) -> KResult<Option<State>> {
    let date = |get: fn(&Attributes) -> Option<OffsetDateTime>| {
        get(owm.attributes()).or_else(|| owm.object().attributes().ok().and_then(get))
    };
    let (activation, deactivation) = match state {
        State::PreActive => (date(|a| a.activation_date), date(|a| a.deactivation_date)),
        State::Active => (None, date(|a| a.deactivation_date)),
        _ => return Ok(None),
    };
    if activation.is_none() && deactivation.is_none() {
        return Ok(None);
    }
    let now = time_normalize()?;
    let active = state == State::Active || activation.is_some_and(|d| d <= now);
    let target = if active && deactivation.is_some_and(|d| d <= now) {
        State::Deactivated
    } else if active {
        State::Active
    } else {
        state
    };
    Ok((target != state).then_some(target))
}

/// Check if a user has permission to perform an operation on an object.
///
/// When OPA is configured, its mode decides which checks run:
///  * `disabled`: only the KMS permission logic below runs.
///  * `exclusive`: OPA alone decides; the KMS permission logic is skipped.
///  * `enforcing`: OPA alone decides (a denial, error or timeout is final, an allow is
///    sufficient), except for native Crypto Officers and ceremony candidates acting on non-HSM
///    objects, who skip OPA and use the KMS permission logic, and for HSM-backed objects, which
///    must also pass the KMS permission logic after OPA allows.
///
/// KMS permission logic:
///  If the user is the owner of the object, it will always return true.
///  An active Crypto Officer is granted every operation on every non-HSM object, across
///  domains (each use is logged as `CRYPTO_OFFICER_ACCESS`), so in `enforcing` mode an active
///  Crypto Officer is effectively outside the OPA policy.
///  For non-HSM objects, having the `Get` permission implies all other operations.
///  For HSM objects, each operation must be explicitly granted (no `Get` wildcard).
///  # Arguments
///  * `user` - The user to check the permission for.
///  * `owm` - The object to check the permission on.
///  * `operation_type` - The operation to check the permission for.
///  * `kms` - The KMS instance.
///  # Returns
///  * `Ok(true)` if the user has permission to perform the operation on the object.
///  * `Ok(false)` if the user does not have permission to perform the operation on the object.
pub(crate) async fn user_has_permission(
    user: &UserId,
    owm: Option<&ObjectWithMetadata>,
    operation_type: &KmipOperation,
    kms: &KMS,
) -> KResult<bool> {
    // ── OPA evaluation (Phase 8, Step 20) ───────────────────────────────────
    if let Some(ref opa_client) = kms.opa_client {
        let mode = kms
            .params
            .opa_params
            .as_ref()
            .map_or(OpaMode::Disabled, |p| p.mode);

        match mode {
            OpaMode::Disabled => { /* fall through to legacy logic */ }
            OpaMode::Exclusive => {
                return Ok(opa_decision(opa_client, mode, user, owm, *operation_type).await);
            }
            OpaMode::Enforcing => {
                // ── Native KMS CO bypass ────────────────────────────────────────────
                // Users listed in `crypto_officer_users` bypass OPA in
                // enforcing mode regardless of whether they have completed the ceremony.
                //
                // Rationale: OPA enforces JWT role/domain policy for external
                // users.  CO candidates are KMS-native — enrolled via server TOML config,
                // not via JWT — and therefore operate outside OPA's role model.
                // Requiring them to pass OPA creates a chicken-and-egg deadlock
                // during the ceremony: candidates must Get peer shares to call
                // JoinSplitKey, but `is_crypto_officer()` returns `false` until
                // the ceremony completes.
                //
                // The bypass applies to BOTH:
                //   a) activated COs   (`is_crypto_officer()` = true)
                //   b) ceremony candidates listed in `co_users` (not yet activated)
                //
                // Both groups are evaluated by the legacy KMS permission logic below:
                //   a) an activated CO reaches the CryptoOfficer bypass there and is
                //      granted every operation on every non-HSM object, across domains
                //      (an audited, deliberate super-admin power outside the OPA policy);
                //   b) a ceremony candidate is held to ownership and explicit DB grants.
                //
                // HSM keys are excluded: their access model is separate and requires
                // explicit HSM-admin grants.
                let object_id = owm.map_or("*", ObjectWithMetadata::id);
                let is_native_co = !ObjectHandle::from(object_id).is_hsm()
                    && (kms.is_crypto_officer(user).await?
                        || kms
                            .params
                            .crypto_officer
                            .users
                            .iter()
                            .any(|u| u == user.as_str()));
                if !is_native_co {
                    // ── OPA ────────────────────────────────────────────────────
                    if !opa_decision(opa_client, mode, user, owm, *operation_type).await {
                        return Ok(false);
                    }
                    // OPA approved. In enforcing mode OPA is the authoritative
                    // role/domain policy engine: it already evaluated `is_owner`,
                    // `same_domain`, and the role hierarchy against the operation.
                    // Trust this decision and return immediately for non-HSM objects
                    // rather than re-evaluating ownership/grants in the KMS legacy gate,
                    // which would deny valid role-based access that OPA explicitly allowed
                    // (e.g. CryptoOfficer reading GetAttributes on a peer's key).
                    // HSM-backed keys still fall through to the HSM-admin / per-HSM-grant
                    // check because their access model is independent of the KMIP
                    // object-grant model and OPA does not evaluate HSM admin status.
                    let is_hsm = owm.is_some_and(|o| ObjectHandle::from(o.id()).is_hsm());
                    if !is_hsm {
                        return Ok(true);
                    }
                }
                // Native CO: fall through to the legacy KMS gate below.
            }
        }
    }

    // ── Legacy KMS permission logic ─────────────────────────────────────────
    let id = match owm {
        Some(object) if user == object.owner() => return Ok(true),
        Some(object) => object.id(),
        None => "*",
    };

    // CryptoOfficer bypass: if the user is an active CryptoOfficer, grant access to
    // all non-HSM objects. HSM-backed keys are governed by the HSM admin rules below
    // and are therefore excluded from this bypass.
    if !ObjectHandle::from(id).is_hsm() && kms.is_crypto_officer(user).await? {
        warn!(
            "CRYPTO_OFFICER_ACCESS: crypto officer {user} bypassed normal permission check on {id} for {operation_type:?}"
        );
        return Ok(true);
    }

    // HSM keys: admins have full access to all keys in their HSM instance(s).
    if ObjectHandle::from(id).is_hsm() {
        let is_hsm_admin = kms
            .params
            .hsm_instances
            .iter()
            .any(|inst| inst.admin.iter().any(|a| a == "*" || a == user));
        if is_hsm_admin {
            return Ok(true);
        }
    }

    let permissions = kms
        .database
        .list_user_operations_on_object(id, user, false)
        .await?;

    // GetAttributes is metadata-only (no key material exposed), so allow it if
    // the user has ANY granted operation on the object. This avoids "Unknown" state
    // in UIs when a user can Locate an object but was only granted e.g. Encrypt.
    if *operation_type == KmipOperation::GetAttributes && !permissions.is_empty() {
        return Ok(true);
    }

    // HSM keys: each operation must be explicitly granted — no generic Get wildcard.
    // Exception: Get and Export are semantically equivalent (both read key material),
    // so holding either permission grants access for both operations.
    if ObjectHandle::from(id).is_hsm() {
        if permissions.contains(operation_type) {
            return Ok(true);
        }
        // Get ↔ Export equivalence for HSM keys
        let get_export_equiv = (*operation_type == KmipOperation::Export
            && permissions.contains(&KmipOperation::Get))
            || (*operation_type == KmipOperation::Get
                && permissions.contains(&KmipOperation::Export));
        return Ok(get_export_equiv);
    }

    Ok(permissions.contains(operation_type) || permissions.contains(&KmipOperation::Get))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::State,
            kmip_2_1::{
                KmipOperation,
                kmip_attributes::Attributes,
                kmip_objects::{Object, OpaqueObject},
                kmip_types::{CryptographicAlgorithm, OpaqueDataType},
                requests::create_symmetric_key_kmip_object,
            },
            time_normalize,
        },
        cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
    };
    use time::Duration;

    use super::{build_opa_input, retrieve_object_for_operation};
    use crate::{
        core::uid_utils::ObjectHandle, error::KmsError, middlewares::UserId, result::KResult,
        tests::test_utils::test_kms,
    };

    // ── Helper ──────────────────────────────────────────────────────────────

    /// Build a minimal `ObjectWithMetadata` for testing.
    ///
    /// Uses `OpaqueObject` (the lightest available `Object` variant) to avoid
    /// constructing crypto key material in unit tests.
    fn make_owm(uid: &str, owner: &str, domain: &str) -> ObjectWithMetadata {
        ObjectWithMetadata::new(
            uid.to_owned(),
            Object::OpaqueObject(OpaqueObject {
                opaque_data_type: OpaqueDataType::Unknown,
                opaque_data_value: uid.as_bytes().to_vec(),
            }),
            owner.to_owned(),
            State::Active,
            Attributes::default(),
            domain.to_owned(),
        )
    }

    // ── Object-less operations (owm = None) ──────────────────────────────────

    /// When `owm` is `None` (object-less operation such as `Create`):
    /// - `object_uid` must be `"*"` (wildcard UID)
    /// - `object_domain` must equal `user_domain` so `same_domain` passes
    /// - `is_owner` must be `false`
    #[test]
    fn test_build_opa_input_objectless_uses_wildcard_uid() {
        let input = build_opa_input(
            "alice@acme.com",
            &["CryptoOfficer".to_owned()],
            Some("acme.com"),
            None,
            KmipOperation::Create,
        );
        assert_eq!(input.object_uid, "*", "object-less op must use '*' UID");
        assert_eq!(
            input.object_domain, "acme.com",
            "object_domain must equal user_domain for object-less ops"
        );
        assert!(
            !input.is_owner,
            "is_owner must be false for object-less ops"
        );
    }

    /// When no user domain is supplied (`None`) for an object-less operation,
    /// both `user_domain` and `object_domain` default to the empty string. The shipped
    /// Rego policy treats an empty domain as "no domain" and never matches it, so such a
    /// caller is denied unless it is a `SuperAdmin`.
    #[test]
    fn test_build_opa_input_objectless_no_domain_defaults_to_empty_string() {
        let input = build_opa_input("alice@acme.com", &[], None, None, KmipOperation::Create);
        assert_eq!(input.user_domain, "");
        assert_eq!(
            input.object_domain, "",
            "object_domain must be '' when user_domain is None"
        );
        assert_eq!(input.object_uid, "*");
    }

    // ── Operations on existing objects ──────────────────────────────────────

    /// When `user == obj.owner()`, `is_owner` must be `true` and the object
    /// UID and domain must be taken from the object (not the wildcard).
    #[test]
    fn test_build_opa_input_owner_sets_is_owner_true() {
        let owm = make_owm("uid-001", "alice@acme.com", "acme.com");
        let input = build_opa_input(
            "alice@acme.com",
            &["CryptoOfficer".to_owned()],
            Some("acme.com"),
            Some(&owm),
            KmipOperation::Get,
        );
        assert!(input.is_owner, "caller must be recognised as owner");
        assert_eq!(input.object_uid, "uid-001");
        assert_eq!(input.object_domain, "acme.com");
    }

    /// When `user != obj.owner()`, `is_owner` must be `false`.
    #[test]
    fn test_build_opa_input_non_owner_sets_is_owner_false() {
        let owm = make_owm("uid-002", "alice@acme.com", "acme.com");
        let input = build_opa_input(
            "bob@acme.com",
            &["CryptoOfficer".to_owned()],
            Some("acme.com"),
            Some(&owm),
            KmipOperation::Get,
        );
        assert!(!input.is_owner, "non-owner must have is_owner=false");
        assert_eq!(input.object_uid, "uid-002");
    }

    /// Object domain is read from the stored object metadata, not from the
    /// user domain.  This is the cross-domain isolation invariant.
    #[test]
    fn test_build_opa_input_object_domain_comes_from_owm() {
        let owm = make_owm("uid-003", "alice@other.com", "other.com");
        let input = build_opa_input(
            "bob@acme.com",
            &["CryptoOfficer".to_owned()],
            Some("acme.com"),
            Some(&owm),
            KmipOperation::Get,
        );
        assert_eq!(input.user_domain, "acme.com");
        assert_eq!(
            input.object_domain, "other.com",
            "object_domain must come from the stored object"
        );
    }

    // ── Operation name format ────────────────────────────────────────────────

    /// `KmipOperation::to_string()` must produce the lowercase `snake_case` names
    /// that the `kms.rego` policy uses for operation set membership tests.
    #[test]
    fn test_build_opa_input_operation_is_lowercase_snake_case() {
        let cases = [
            (KmipOperation::Create, "create"),
            (KmipOperation::Get, "get"),
            (KmipOperation::GetAttributes, "get_attributes"),
            (KmipOperation::Destroy, "destroy"),
            (KmipOperation::Locate, "locate"),
        ];
        for (op, expected) in cases {
            let input = build_opa_input("u", &[], None, None, op);
            assert_eq!(
                input.operation, expected,
                "KmipOperation::{op:?} must serialize to '{expected}'"
            );
        }
    }

    // ── Roles and user identity passthrough ──────────────────────────────────

    /// Roles are passed through unchanged; they are never modified by
    /// `build_opa_input` (KMS is role-vocabulary-agnostic).
    #[test]
    fn test_build_opa_input_roles_passed_through_unchanged() {
        let roles = vec!["CryptoOfficer".to_owned(), "Auditor".to_owned()];
        let input = build_opa_input("u", &roles, None, None, KmipOperation::Create);
        assert_eq!(input.roles, roles);
    }

    /// The user identity is copied verbatim to `input.user`.
    #[test]
    fn test_build_opa_input_user_identity_is_preserved() {
        let input = build_opa_input(
            "alice@tenant.example",
            &[],
            None,
            None,
            KmipOperation::Create,
        );
        assert_eq!(input.user, "alice@tenant.example");
    }

    // ── Time-based lifecycle transitions ─────────────────────────────────────

    /// A time-based transition persisted during retrieval bumps the stored version: the
    /// returned object must be the refreshed store snapshot (persisted state, current
    /// version), so a version-guarded write by the caller does not conflict with the
    /// retrieval's own write. Covers transition 4, transition 6, and both chained.
    #[tokio::test]
    async fn test_auto_transition_returns_refreshed_snapshot() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("retrieve_refresh_owner@example.com");
        let past = time_normalize()? - Duration::hours(1);
        let cases = [
            (State::PreActive, Some(past), None, State::Active),
            (State::Active, None, Some(past), State::Deactivated),
            (State::PreActive, Some(past), Some(past), State::Deactivated),
        ];
        for (stored_state, activation_date, deactivation_date, expected) in cases {
            let attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                state: Some(stored_state),
                activation_date,
                deactivation_date,
                ..Attributes::default()
            };
            let object = create_symmetric_key_kmip_object("x-vendor", &[7_u8; 32], &attributes)?;
            let uid = kms
                .database
                .create(None, &owner, &object, &attributes, &HashSet::new(), "")
                .await?;

            let owm = retrieve_object_for_operation(
                ObjectHandle::from(uid.as_str()),
                KmipOperation::GetAttributes,
                &kms,
                &owner,
            )
            .await?;

            let stored = kms
                .database
                .retrieve_object(&uid)
                .await?
                .expect("object must still exist");
            let case = format!("{stored_state} → {expected}");
            assert_eq!(stored.state(), expected, "{case}: transition persisted");
            assert_eq!(owm.state(), expected, "{case}: returned state");
            assert_eq!(owm.attributes().state, Some(expected), "{case}: attributes");
            assert!(owm.version().is_some(), "{case}: SQLite tracks versions");
            assert_eq!(owm.version(), stored.version(), "{case}: returned version");
        }
        Ok(())
    }

    /// `Activate` must see a `PreActive` object even when its `ActivationDate` has passed,
    /// otherwise the explicit Activate would be rejected as Active → Active.
    #[tokio::test]
    async fn test_activate_retrieval_skips_auto_transition() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("retrieve_activate_owner@example.com");
        let attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::PreActive),
            activation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Attributes::default()
        };
        let object = create_symmetric_key_kmip_object("x-vendor", &[7_u8; 32], &attributes)?;
        let uid = kms
            .database
            .create(None, &owner, &object, &attributes, &HashSet::new(), "")
            .await?;
        let owm = retrieve_object_for_operation(
            ObjectHandle::from(uid.as_str()),
            KmipOperation::Activate,
            &kms,
            &owner,
        )
        .await?;
        assert_eq!(owm.state(), State::PreActive);
        Ok(())
    }

    /// The refresh must not weaken the optimistic lock: a write landing after the
    /// refreshed snapshot was read still rejects a writer holding that snapshot's version.
    #[tokio::test]
    async fn test_auto_transition_refresh_keeps_optimistic_lock() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("retrieve_refresh_lock_owner@example.com");
        let attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            deactivation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Attributes::default()
        };
        let object = create_symmetric_key_kmip_object("x-vendor", &[7_u8; 32], &attributes)?;
        let uid = kms
            .database
            .create(None, &owner, &object, &attributes, &HashSet::new(), "")
            .await?;
        let owm = retrieve_object_for_operation(
            ObjectHandle::from(uid.as_str()),
            KmipOperation::GetAttributes,
            &kms,
            &owner,
        )
        .await?;
        let version = owm.version().expect("SQLite tracks versions");

        // Concurrent writer lands after the refresh.
        kms.database
            .update_object(&uid, owm.object(), owm.attributes(), None)
            .await?;

        let mut stale_attributes = owm.attributes().clone();
        stale_attributes.rotate_interval = Some(42);
        let err = kms
            .database
            .atomic(
                &owner,
                &[AtomicOperation::UpdateObjectIfVersion((
                    uid.clone(),
                    owm.object().clone(),
                    stale_attributes,
                    None,
                    version,
                ))],
            )
            .await
            .expect_err("a write holding the pre-concurrent-write version must be rejected");
        let err = KmsError::from(err);
        assert!(matches!(err, KmsError::Conflict(_)), "{err:?}");
        let stored = kms
            .database
            .retrieve_object(&uid)
            .await?
            .expect("object must still exist");
        assert_ne!(stored.attributes().rotate_interval, Some(42));
        assert_eq!(stored.version(), Some(version + 1));
        Ok(())
    }
}
