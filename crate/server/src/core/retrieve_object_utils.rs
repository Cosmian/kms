use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::KmipOperation,
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};

use crate::{
    core::{
        KMS,
        opa::{OpaInput, OpaMode, get_opa_user_context},
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
pub(crate) async fn retrieve_object_for_operation(
    object_handle: ObjectHandle<'_>,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &UserId,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "object_handle: {object_handle}, user: {user}, \
         operation_type: {operation_type:?}",
    );

    for owm in kms.database.retrieve_objects(object_handle).await?.values() {
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
            ),
            State::Destroyed | State::Destroyed_Compromised => {
                // KMIP profiles expect Get on a destroyed object to return OperationFailed / ObjectDestroyed
                // rather than ObjectNotFound. We therefore allow retrieval for Get so the operation layer
                // can emit the correct Object_Destroyed error (BL-M-8-21 vector). Still restrict other
                // operations besides GetAttributes and Get.
                // Similarly, Activate on a destroyed object must return Wrong_Key_Lifecycle_State
                // ("cannot be activated") rather than Object_Not_Found; allow retrieval so activate.rs
                // can emit the correct lifecycle error.
                matches!(
                    operation_type,
                    KmipOperation::Get | KmipOperation::GetAttributes | KmipOperation::Activate
                )
            }
        };
        if !state_allows {
            trace!(
                "state_allows: {state_allows}: state: {state}, operation_type: {operation_type}"
            );
            continue;
        }

        if user_has_permission(user, Some(owm), &operation_type, kms).await? {
            trace!(
                "User {user} has permission for operation {operation_type:?} on object {}",
                owm.id()
            );
            let mut owm = owm.to_owned();
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
            // Synchronize both external attributes and embedded object attributes to effective state
            owm.attributes_mut().state = Some(effective_state);
            if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                attributes.state = Some(effective_state);
            }

            // KMIP 2.1 Auto-activation: PreActive → Active when ActivationDate has passed (§4.57 transition 4)
            if effective_state == State::PreActive {
                let activation_date = owm.attributes().activation_date.or_else(|| {
                    owm.object()
                        .attributes()
                        .ok()
                        .and_then(|attrs| attrs.activation_date)
                });

                if let Some(activation_date) = activation_date {
                    let now = time_normalize()?;
                    if activation_date <= now {
                        trace!(
                            "Auto-activating object {} (activation_date {} <= now {})",
                            owm.id(),
                            activation_date,
                            now
                        );
                        owm.attributes_mut().state = Some(State::Active);
                        if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                            attributes.state = Some(State::Active);
                        }
                        if let Err(e) = kms.database.update_state(owm.id(), State::Active).await {
                            warn!(
                                "Failed to persist auto-activation of object {}: {}",
                                owm.id(),
                                e
                            );
                        }
                        // Re-check: the now-Active key may also need auto-deactivation
                        let deactivation_date = owm.attributes().deactivation_date.or_else(|| {
                            owm.object()
                                .attributes()
                                .ok()
                                .and_then(|attrs| attrs.deactivation_date)
                        });
                        if let Some(deactivation_date) = deactivation_date {
                            if deactivation_date <= now {
                                trace!(
                                    "Auto-deactivating object {} (deactivation_date {} <= now {})",
                                    owm.id(),
                                    deactivation_date,
                                    now
                                );
                                owm.attributes_mut().state = Some(State::Deactivated);
                                if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                                    attributes.state = Some(State::Deactivated);
                                }
                                if let Err(e) = kms
                                    .database
                                    .update_state(owm.id(), State::Deactivated)
                                    .await
                                {
                                    warn!(
                                        "Failed to persist auto-deactivation of object {}: {}",
                                        owm.id(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // KMIP 2.1 Auto-deactivation: Active → Deactivated when DeactivationDate has passed (§4.57 transition 6)
            if owm.attributes().state == Some(State::Active) {
                let deactivation_date = owm.attributes().deactivation_date.or_else(|| {
                    owm.object()
                        .attributes()
                        .ok()
                        .and_then(|attrs| attrs.deactivation_date)
                });

                if let Some(deactivation_date) = deactivation_date {
                    let now = time_normalize()?;
                    if deactivation_date <= now {
                        trace!(
                            "Auto-deactivating object {} (deactivation_date {} <= now {})",
                            owm.id(),
                            deactivation_date,
                            now
                        );
                        owm.attributes_mut().state = Some(State::Deactivated);
                        if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                            attributes.state = Some(State::Deactivated);
                        }
                        if let Err(e) = kms
                            .database
                            .update_state(owm.id(), State::Deactivated)
                            .await
                        {
                            warn!(
                                "Failed to persist auto-deactivation of object {}: {}",
                                owm.id(),
                                e
                            );
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
            if !skip_unwrap {
                if let Some(defaults) = &kms.params.default_unwrap_types {
                    if defaults.contains(&owm.object().object_type())
                        && state != State::Destroyed
                        && state != State::Destroyed_Compromised
                    {
                        let unwrapped_object =
                            Box::pin(kms.get_unwrapped(owm.id(), owm.object(), user)).await?;
                        owm.set_object(unwrapped_object);
                    }
                }
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
                // object domain from the caller's domain so that same_domain rules pass.
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

/// Check if a user has permission to perform an operation on an object.
///  If the user is the owner of the object, it will always return true.
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
                let opa_ctx = get_opa_user_context();
                let input = build_opa_input(
                    user,
                    &opa_ctx.roles,
                    opa_ctx.domain.as_deref(),
                    owm,
                    *operation_type,
                );
                let allowed = opa_client.query(&input).await.unwrap_or(false);
                trace!(
                    "OPA exclusive decision for user={} op={} obj={}: {}",
                    user, operation_type, input.object_uid, allowed
                );
                return Ok(allowed);
            }
            OpaMode::Enforcing => {
                // ── Native KMS CO bypass ────────────────────────────────────────────
                // Users listed in `crypto_officer_users` bypass OPA Gate 1 in
                // enforcing mode regardless of whether they have completed the ceremony.
                //
                // Rationale: OPA Gate 1 enforces JWT role/domain policy for external
                // users.  CO candidates are KMS-native — enrolled via server TOML config,
                // not via JWT — and therefore operate outside OPA's role model.
                // Requiring them to pass OPA Gate 1 creates a chicken-and-egg deadlock
                // during the ceremony: candidates must Get peer shares to call
                // JoinSplitKey, but `is_crypto_officer()` returns `false` until
                // the ceremony completes.
                //
                // The bypass applies to BOTH:
                //   a) activated COs   (`is_crypto_officer()` = true)
                //   b) ceremony candidates listed in `co_users` (not yet activated)
                //
                // Both groups fall through to the legacy KMS gate, which enforces
                // ownership and explicit DB grant checks — so bypassing OPA Gate 1
                // does NOT grant unconditional access.
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
                    // ── OPA Gate 1 ────────────────────────────────────────────────────
                    let opa_ctx = get_opa_user_context();
                    let input = build_opa_input(
                        user,
                        &opa_ctx.roles,
                        opa_ctx.domain.as_deref(),
                        owm,
                        *operation_type,
                    );
                    let allowed = opa_client.query(&input).await.unwrap_or(false);
                    trace!(
                        "OPA enforcing decision for user={} op={} obj={}: {}",
                        user, operation_type, input.object_uid, allowed
                    );
                    if !allowed {
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
