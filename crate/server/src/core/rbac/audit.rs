//! RBAC Audit Logger
//!
//! Emits structured `tracing::info!` events for every RBAC authorization decision.
//! Events are exported via the existing OTEL tracing pipeline.

use tracing::info;

use super::{evaluator::PolicyDecision, input_builder::PolicyInput};

/// Emit a structured audit event for an RBAC authorization decision.
///
/// Both allow and deny decisions are logged for compliance traceability.
/// The `bundle_hash` links each decision to the specific policy version that produced it.
pub fn emit_rbac_audit(input: &PolicyInput, decision: &PolicyDecision, bundle_hash: &str) {
    let resource_id = input.resource.as_ref().map_or("-", |r| r.id.as_str());
    let tenant_id = input.subject.tenant_id.as_deref().unwrap_or("-");
    let decision_str = if decision.allowed { "allow" } else { "deny" };
    let reason = decision.reason.as_deref().unwrap_or("-");

    info!(
        target: "kms::rbac::audit",
        user = %input.subject.user_id,
        operation = %input.operation.kmip_op,
        resource_id = %resource_id,
        tenant_id = %tenant_id,
        decision = %decision_str,
        reason = %reason,
        bundle_hash = %bundle_hash,
        "RBAC authorization decision"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rbac::input_builder::{
        OperationContext, PolicyInput, RequestContext, Subject,
    };

    #[test]
    fn test_emit_rbac_audit_does_not_panic() {
        let input = PolicyInput::for_non_object_operation(
            Subject {
                user_id: "alice@test.com".to_owned(),
                roles: vec!["operator".to_owned()],
                tenant_id: Some("tenant-1".to_owned()),
                is_privileged: false,
            },
            RequestContext {
                ip: None,
                tls_subject: None,
                user_agent: None,
            },
            OperationContext {
                kmip_op: "Create".to_owned(),
                algorithm: None,
                mode: None,
                padding: None,
                target_user: None,
                grant_ops: None,
            },
        );
        let decision = PolicyDecision {
            allowed: true,
            reason: Some("admin role".to_owned()),
        };

        // Should not panic
        emit_rbac_audit(&input, &decision, "abc123");
    }
}
