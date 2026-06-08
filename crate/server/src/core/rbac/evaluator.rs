//! Policy Evaluator
//!
//! Wraps the Regorus policy source behind `ArcSwap` for atomic hot-reload.
//! Provides the `evaluate()` API that takes a policy input and returns a `PolicyDecision`.
//!
//! A fresh `regorus::Engine` is built per evaluation from the stored policy source.
//! This avoids `Send`/`Sync` issues with `regorus::Engine` while keeping the interface
//! thread-safe. For the small policy bundles used in KMS RBAC, engine construction
//! is sub-millisecond and acceptable overhead.

use std::sync::Arc;

use arc_swap::ArcSwap;
use regorus::Value;

use super::bundle_manager::RegoFile;
use crate::{error::KmsError, result::KResult};

/// The decision path queried in the Rego policy.
const DECISION_PATH: &str = "data.kms.authz.allow";
/// The reason path queried in the Rego policy (optional).
const REASON_PATH: &str = "data.kms.authz.reason";

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Optional reason string (for audit logging, not returned to client).
    pub reason: Option<String>,
}

/// Immutable, `Send + Sync` policy source stored behind `ArcSwap`.
#[derive(Clone)]
struct PolicySource {
    /// The Rego source files.
    files: Vec<RegoFile>,
    /// Allowlists JSON (loaded as `data.kms.config.allowlists`).
    allowlists_json: String,
    /// Content-only bundle hash for audit logging.
    bundle_hash: String,
}

/// Thread-safe policy evaluator backed by Regorus.
///
/// Uses `ArcSwap` for atomic policy source replacement during hot-reload.
/// Each evaluation builds a fresh `regorus::Engine` from the stored source —
/// this avoids `Send`/`Sync` constraints on the engine while keeping the
/// evaluator fully thread-safe.
pub struct PolicyEvaluator {
    source: ArcSwap<PolicySource>,
}

impl PolicyEvaluator {
    /// Create a new evaluator from a set of Rego files and optional allowlists data.
    ///
    /// Validates the bundle by compiling it once; subsequent evaluations rebuild from source.
    ///
    /// # Errors
    /// Returns an error if any Rego file fails to compile or data cannot be loaded.
    pub fn new(
        rego_files: &[RegoFile],
        allowlists_json: &str,
        bundle_hash: String,
    ) -> KResult<Self> {
        // Validate by building the engine once
        Self::build_engine(rego_files, allowlists_json)?;

        Ok(Self {
            source: ArcSwap::new(Arc::new(PolicySource {
                files: rego_files.to_vec(),
                allowlists_json: allowlists_json.to_owned(),
                bundle_hash,
            })),
        })
    }

    /// Evaluate the policy with the given input JSON value.
    ///
    /// Returns `PolicyDecision { allowed, reason }`.
    /// On evaluation errors or engine build failures, returns `allowed: false` (fail-closed).
    pub fn evaluate(&self, input: &Value) -> PolicyDecision {
        let source = self.source.load();

        let Ok(mut engine) = Self::build_engine(&source.files, &source.allowlists_json) else {
            return PolicyDecision {
                allowed: false,
                reason: Some("engine build failed".to_owned()),
            };
        };

        engine.set_input(input.clone());

        // Evaluate the allow decision (fail-closed on error)
        let allowed = engine
            .eval_rule(DECISION_PATH.to_owned())
            .is_ok_and(|value| value_to_bool(&value));

        // Evaluate the reason (optional, best-effort)
        let reason = engine
            .eval_rule(REASON_PATH.to_owned())
            .ok()
            .and_then(|v| value_to_string(&v));

        PolicyDecision { allowed, reason }
    }

    /// Returns the current bundle hash (for audit logging).
    pub fn bundle_hash(&self) -> String {
        self.source.load().bundle_hash.clone()
    }

    /// Atomically reload the policy with a new bundle.
    ///
    /// Validates the new bundle by compiling it once, then swaps the source atomically.
    /// In-flight evaluations that already loaded the old source will finish with the old policy.
    ///
    /// # Errors
    /// Returns an error if the new bundle fails validation. The old policy remains active.
    pub fn reload(
        &self,
        rego_files: &[RegoFile],
        allowlists_json: &str,
        bundle_hash: String,
    ) -> KResult<()> {
        // Validate before swapping
        Self::build_engine(rego_files, allowlists_json)?;

        let new_source = Arc::new(PolicySource {
            files: rego_files.to_vec(),
            allowlists_json: allowlists_json.to_owned(),
            bundle_hash,
        });
        self.source.store(new_source);
        Ok(())
    }

    /// Build a Regorus engine from Rego files and allowlists data.
    fn build_engine(rego_files: &[RegoFile], allowlists_json: &str) -> KResult<regorus::Engine> {
        let mut engine = regorus::Engine::new();

        for file in rego_files {
            engine
                .add_policy(file.filename.clone(), file.content.clone())
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "Failed to add Rego policy '{}': {e}",
                        file.filename
                    ))
                })?;
        }

        if !allowlists_json.is_empty() && allowlists_json != "{}" {
            let data_json = format!(r#"{{"kms":{{"config":{{"allowlists":{allowlists_json}}}}}}}"#);
            let data_value = Value::from_json_str(&data_json).map_err(|e| {
                KmsError::ServerError(format!("Failed to parse allowlists JSON as OPA data: {e}"))
            })?;
            engine.add_data(data_value).map_err(|e| {
                KmsError::ServerError(format!("Failed to load allowlists into Regorus: {e}"))
            })?;
        }

        Ok(engine)
    }
}

/// Extract a boolean from a Regorus Value.
const fn value_to_bool(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        _ => false,
    }
}

/// Extract a string from a Regorus Value.
fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rbac::bundle_manager::RegoFile;

    fn simple_allow_policy() -> Vec<RegoFile> {
        vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: r#"
package kms.authz

import rego.v1

default allow := false

allow if {
    input.subject.roles[_] == "admin"
}

reason := "admin role grants access"
"#
            .to_owned(),
        }]
    }

    #[test]
    fn test_evaluator_allows_admin() {
        let evaluator =
            PolicyEvaluator::new(&simple_allow_policy(), "{}", "test-hash".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{"subject": {"user_id": "alice", "roles": ["admin"], "tenant_id": "t1"}}"#,
        )
        .unwrap();

        let decision = evaluator.evaluate(&input);
        assert!(decision.allowed);
        assert_eq!(decision.reason.as_deref(), Some("admin role grants access"));
    }

    #[test]
    fn test_evaluator_denies_non_admin() {
        let evaluator =
            PolicyEvaluator::new(&simple_allow_policy(), "{}", "test-hash".to_owned()).unwrap();

        let input = Value::from_json_str(
            r#"{"subject": {"user_id": "bob", "roles": ["auditor"], "tenant_id": "t1"}}"#,
        )
        .unwrap();

        let decision = evaluator.evaluate(&input);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_evaluator_fail_closed_on_empty_input() {
        let evaluator =
            PolicyEvaluator::new(&simple_allow_policy(), "{}", "test-hash".to_owned()).unwrap();

        let input = Value::from_json_str(r#"{}"#).unwrap();
        let decision = evaluator.evaluate(&input);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_evaluator_reload_changes_behavior() {
        let initial_policy = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "package kms.authz\nimport rego.v1\ndefault allow := true\n".to_owned(),
        }];

        let evaluator = PolicyEvaluator::new(&initial_policy, "{}", "hash-v1".to_owned()).unwrap();

        let input = Value::from_json_str(r#"{"subject": {"roles": []}}"#).unwrap();
        assert!(evaluator.evaluate(&input).allowed);
        assert_eq!(evaluator.bundle_hash(), "hash-v1");

        // Reload with a deny-all policy
        let deny_policy = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "package kms.authz\nimport rego.v1\ndefault allow := false\n".to_owned(),
        }];
        evaluator
            .reload(&deny_policy, "{}", "hash-v2".to_owned())
            .unwrap();

        assert!(!evaluator.evaluate(&input).allowed);
        assert_eq!(evaluator.bundle_hash(), "hash-v2");
    }

    #[test]
    fn test_evaluator_with_allowlists_data() {
        let policy = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: r#"
package kms.authz

import rego.v1

default allow := false

allow if {
    input.operation.algorithm in data.kms.config.allowlists.algorithms
}
"#
            .to_owned(),
        }];

        let allowlists = r#"{"algorithms": ["AES", "RSA"]}"#;
        let evaluator = PolicyEvaluator::new(&policy, allowlists, "test-hash".to_owned()).unwrap();

        // AES is in the allowlist
        let input_aes = Value::from_json_str(r#"{"operation": {"algorithm": "AES"}}"#).unwrap();
        assert!(evaluator.evaluate(&input_aes).allowed);

        // ChaCha20 is not in the allowlist
        let input_chacha =
            Value::from_json_str(r#"{"operation": {"algorithm": "ChaCha20"}}"#).unwrap();
        assert!(!evaluator.evaluate(&input_chacha).allowed);
    }
}
