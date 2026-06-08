//! RBAC Enforcement helpers for the dispatch layer.
//!
//! Provides the `enforce_rbac_pre_dispatch` function that checks whether
//! a KMIP operation is allowed before it executes.

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::ErrorReason;
use cosmian_logger::trace;

use crate::{
    core::{
        KMS,
        rbac::{
            audit::emit_rbac_audit,
            input_builder::{OperationContext, PolicyInput, RequestContext, Subject},
        },
    },
    error::KmsError,
    result::KResult,
};

/// Operations exempt from RBAC enforcement (protocol-level, no key material).
const EXEMPT_OPERATIONS: &[&str] = &["DiscoverVersions", "Query"];

/// Pre-dispatch RBAC enforcement (Tier 1).
///
/// For non-object operations (Create, `CreateKeyPair`, etc.), evaluates the policy
/// BEFORE the operation executes. Exempt operations (`DiscoverVersions`, `Query`)
/// always pass.
///
/// Returns `Ok(())` if allowed, or `Err(Permission_Denied)` if denied.
pub(crate) fn enforce_rbac_pre_dispatch(
    kms: &KMS,
    operation_tag: &str,
    user: &str,
    roles: &[String],
    tenant_id: Option<&str>,
) -> KResult<()> {
    // Skip if no evaluator configured
    let Some(evaluator) = kms.rbac_evaluator() else {
        return Ok(());
    };

    // Skip exempt operations
    if EXEMPT_OPERATIONS.contains(&operation_tag) {
        return Ok(());
    }

    // Skip if RBAC is not fully enabled (evaluator exists for algorithm-only mode,
    // but we only enforce role/tenant checks when rbac.enabled is true)
    if !kms.params.rbac.enabled {
        return Ok(());
    }

    trace!(
        "RBAC pre-dispatch: user={user}, op={operation_tag}, roles={roles:?}, tenant={tenant_id:?}"
    );

    // Determine if user is privileged (super-admin via config)
    let is_privileged = kms
        .params
        .privileged_users
        .as_ref()
        .is_some_and(|pu| pu.iter().any(|p| p == user));
    let is_super_admin = kms.params.rbac.super_admins.iter().any(|sa| sa == user);

    let subject = Subject {
        user_id: user.to_owned(),
        roles: if is_super_admin {
            let mut r = roles.to_vec();
            if !r.contains(&"super-admin".to_owned()) {
                r.push("super-admin".to_owned());
            }
            r
        } else {
            roles.to_vec()
        },
        tenant_id: tenant_id.map(String::from),
        is_privileged,
    };

    let input = PolicyInput::for_non_object_operation(
        subject,
        RequestContext {
            ip: None,
            tls_subject: None,
            user_agent: None,
        },
        OperationContext {
            kmip_op: operation_tag.to_owned(),
            algorithm: None,
            mode: None,
            padding: None,
            target_user: None,
            grant_ops: None,
        },
    );

    let regorus_input = input
        .to_regorus_value()
        .map_err(|e| KmsError::ServerError(format!("Failed to build RBAC input: {e}")))?;

    let decision = evaluator.evaluate(&regorus_input);
    let bundle_hash = evaluator.bundle_hash();

    // Emit audit event
    emit_rbac_audit(&input, &decision, &bundle_hash);

    if decision.allowed {
        Ok(())
    } else {
        Err(KmsError::Kmip21Error(
            ErrorReason::Permission_Denied,
            "authorization denied".to_owned(),
        ))
    }
}
