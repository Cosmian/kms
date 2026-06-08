//! Default embedded policy bundles.
//!
//! These policies are compiled into the binary via `include_str!` so the server
//! can start without an external bundle path in non-RBAC mode.

use super::bundle_manager::RegoFile;

/// The algorithm-only policy used when RBAC is disabled.
/// Only enforces the `data.kms.config.allowlists` algorithm restrictions.
const ALGORITHM_ONLY_POLICY: &str = include_str!("default_policies/algorithm_only.rego");

/// The full RBAC policy used as the default when RBAC is enabled
/// but no custom bundle is provided (or for reference/documentation).
const FULL_RBAC_POLICY: &str = include_str!("default_policies/authz.rego");

/// Returns the embedded algorithm-only policy as a `RegoFile` slice.
///
/// Used when RBAC is disabled — provides algorithm enforcement without
/// roles, tenants, or ACL logic.
pub fn algorithm_only_bundle() -> Vec<RegoFile> {
    vec![RegoFile {
        filename: "authz.rego".to_owned(),
        content: ALGORITHM_ONLY_POLICY.to_owned(),
    }]
}

/// Returns the embedded full RBAC policy as a `RegoFile` slice.
///
/// This is the default policy bundle for RBAC mode with the standard
/// role hierarchy: super-admin > admin > operator > auditor.
pub fn full_rbac_bundle() -> Vec<RegoFile> {
    vec![RegoFile {
        filename: "authz.rego".to_owned(),
        content: FULL_RBAC_POLICY.to_owned(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rbac::{bundle_manager::validate_bundle, evaluator::PolicyEvaluator};
    use regorus::Value;

    #[test]
    fn test_algorithm_only_bundle_compiles() {
        let bundle = algorithm_only_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    #[test]
    fn test_full_rbac_bundle_compiles() {
        let bundle = full_rbac_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    #[test]
    fn test_algorithm_only_allows_without_allowlist() {
        let bundle = algorithm_only_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        let input =
            Value::from_json_str(r#"{"operation": {"algorithm": "AES", "kmip_op": "Create"}}"#)
                .unwrap();
        // No allowlists configured → allow
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_algorithm_only_denies_unlisted_algorithm() {
        let bundle = algorithm_only_bundle();
        let allowlists = r#"{"algorithms": ["AES", "RSA"]}"#;
        let evaluator = PolicyEvaluator::new(&bundle, allowlists, "test".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{"operation": {"algorithm": "ChaCha20", "kmip_op": "Create"}}"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_admin_allows() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "alice", "roles": ["admin"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Create", "algorithm": null},
                "resource": null,
                "acl": null
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_auditor_denied_create() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "bob", "roles": ["auditor"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Create", "algorithm": null},
                "resource": null,
                "acl": null
            }"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_tenant_isolation() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Admin in tenant-1 accessing resource in tenant-2: denied
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "alice", "roles": ["admin"], "tenant_id": "tenant-1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Get", "algorithm": null},
                "resource": {"id": "key-1", "owner": "bob", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "tenant-2"},
                "acl": {"is_owner": false, "granted_ops": []}
            }"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_super_admin_cross_tenant() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Super-admin can access any tenant
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "ops", "roles": ["super-admin"], "tenant_id": "ops-tenant", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Get", "algorithm": null},
                "resource": {"id": "key-1", "owner": "bob", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "other-tenant"},
                "acl": {"is_owner": false, "granted_ops": ["Get"]}
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_no_role_denied() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // User with no roles: denied even if owner
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "alice", "roles": [], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Get", "algorithm": null},
                "resource": {"id": "key-1", "owner": "alice", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "t1"},
                "acl": {"is_owner": true, "granted_ops": []}
            }"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_operator_can_encrypt() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "op1", "roles": ["operator"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Encrypt", "algorithm": null},
                "resource": {"id": "key-1", "owner": "op1", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "t1"},
                "acl": {"is_owner": true, "granted_ops": []}
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_operator_denied_without_access() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Operator trying to access another user's object without grant
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "op1", "roles": ["operator"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Decrypt", "algorithm": null},
                "resource": {"id": "key-2", "owner": "other", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "t1"},
                "acl": {"is_owner": false, "granted_ops": []}
            }"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_operator_allowed_with_grant() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Operator accessing another user's object WITH explicit grant
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "op1", "roles": ["operator"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Decrypt", "algorithm": null},
                "resource": {"id": "key-2", "owner": "other", "type": "SymmetricKey", "state": "Active", "tags": [], "tenant_id": "t1"},
                "acl": {"is_owner": false, "granted_ops": ["Decrypt"]}
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_privileged_user_allowed() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Privileged user with no explicit roles can still operate
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "svc-account", "roles": [], "tenant_id": "t1", "is_privileged": true},
                "request": {},
                "operation": {"kmip_op": "Create", "algorithm": null},
                "resource": null,
                "acl": null
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_algorithm_denied() {
        let bundle = full_rbac_bundle();
        let allowlists = r#"{"algorithms": ["AES", "RSA"]}"#;
        let evaluator = PolicyEvaluator::new(&bundle, allowlists, "test".to_owned()).unwrap();

        // Admin with disallowed algorithm: denied
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "admin1", "roles": ["admin"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Create", "algorithm": "ChaCha20"},
                "resource": null,
                "acl": null
            }"#,
        )
        .unwrap();
        assert!(!evaluator.evaluate(&input).allowed);
    }

    #[test]
    fn test_full_rbac_role_hierarchy_operator_inherits_auditor() {
        let bundle = full_rbac_bundle();
        let evaluator = PolicyEvaluator::new(&bundle, "{}", "test".to_owned()).unwrap();

        // Operator can do auditor operations (Locate) due to hierarchy
        let input = Value::from_json_str(
            r#"{
                "subject": {"user_id": "op1", "roles": ["operator"], "tenant_id": "t1", "is_privileged": false},
                "request": {},
                "operation": {"kmip_op": "Locate", "algorithm": null},
                "resource": null,
                "acl": null
            }"#,
        )
        .unwrap();
        assert!(evaluator.evaluate(&input).allowed);
    }
}
