use std::path::{Path, PathBuf};

use cosmian_logger::{debug, info};
use regorus::Engine;

use crate::{RbacResult, engine::RbacEngine, error::RbacError, input::RbacInput};

/// The default Rego policy shipped with the KMS.
const DEFAULT_POLICY: &str = include_str!("../../../resources/rbac/default_rbac.rego");

/// A named policy source (filename + Rego source code).
struct PolicySource {
    name: String,
    source: String,
}

/// Embedded Rego policy engine backed by `regorus`.
///
/// Loads `.rego` policy files at construction time and evaluates
/// authorization requests by creating a fresh interpreter per call.
/// `regorus::Engine` is neither `Send` nor `Sync`, so we store the
/// parsed policy sources and build a short-lived engine for each evaluation.
pub struct RegorusEngine {
    /// Parsed policy sources to load into each fresh engine.
    policies: Vec<PolicySource>,
    /// Path(s) from which policies were loaded (for diagnostics).
    policy_paths: Vec<PathBuf>,
}

impl RegorusEngine {
    /// Create a new engine from a path to a `.rego` file or a directory
    /// containing `.rego` files.
    ///
    /// If `policy_path` is `None`, the built-in default policy is loaded.
    ///
    /// # Errors
    /// Returns an error if policy files cannot be read or parsed.
    pub fn new(policy_path: Option<&Path>) -> RbacResult<Self> {
        let mut policies = Vec::new();
        let mut policy_paths = Vec::new();

        // Validate policies by loading them into a throw-away engine
        let mut validation_engine = Engine::new();

        match policy_path {
            Some(path) if path.is_dir() => {
                let entries = std::fs::read_dir(path).map_err(|e| {
                    RbacError::PolicyFile(format!(
                        "cannot read RBAC policy directory {}: {e}",
                        path.display()
                    ))
                })?;
                for entry in entries {
                    let entry = entry.map_err(|e| {
                        RbacError::PolicyFile(format!("cannot read directory entry: {e}"))
                    })?;
                    let file_path = entry.path();
                    if file_path.extension().is_some_and(|ext| ext == "rego") {
                        let source = std::fs::read_to_string(&file_path).map_err(|e| {
                            RbacError::PolicyFile(format!(
                                "cannot read policy file {}: {e}",
                                file_path.display()
                            ))
                        })?;
                        let name = file_path.to_string_lossy().to_string();
                        validation_engine
                            .add_policy(name.clone(), source.clone())
                            .map_err(|e| {
                                RbacError::PolicyEvaluation(format!(
                                    "failed to parse policy {}: {e}",
                                    file_path.display()
                                ))
                            })?;
                        info!("RBAC: loaded policy file {:?}", file_path);
                        policies.push(PolicySource { name, source });
                        policy_paths.push(file_path);
                    }
                }
                if policy_paths.is_empty() {
                    return Err(RbacError::PolicyFile(format!(
                        "no .rego files found in directory {}",
                        path.display()
                    )));
                }
            }
            Some(path) => {
                let source = std::fs::read_to_string(path).map_err(|e| {
                    RbacError::PolicyFile(format!(
                        "cannot read policy file {}: {e}",
                        path.display()
                    ))
                })?;
                let name = path.to_string_lossy().to_string();
                validation_engine
                    .add_policy(name.clone(), source.clone())
                    .map_err(|e| {
                        RbacError::PolicyEvaluation(format!(
                            "failed to parse policy {}: {e}",
                            path.display()
                        ))
                    })?;
                info!("RBAC: loaded policy file {:?}", path);
                policies.push(PolicySource { name, source });
                policy_paths.push(path.to_path_buf());
            }
            None => {
                validation_engine
                    .add_policy("default_rbac.rego".to_owned(), DEFAULT_POLICY.to_owned())
                    .map_err(|e| {
                        RbacError::PolicyEvaluation(format!(
                            "failed to parse built-in default policy: {e}"
                        ))
                    })?;
                info!("RBAC: loaded built-in default policy");
                policies.push(PolicySource {
                    name: "default_rbac.rego".to_owned(),
                    source: DEFAULT_POLICY.to_owned(),
                });
                policy_paths.push(PathBuf::from("(built-in default)"));
            }
        }

        Ok(Self {
            policies,
            policy_paths,
        })
    }

    /// Return the paths of policies that were loaded.
    #[must_use]
    pub fn policy_paths(&self) -> &[PathBuf] {
        &self.policy_paths
    }

    /// Build a fresh regorus engine with all policies loaded.
    fn build_engine(&self) -> RbacResult<Engine> {
        let mut engine = Engine::new();
        for policy in &self.policies {
            engine
                .add_policy(policy.name.clone(), policy.source.clone())
                .map_err(|e| {
                    RbacError::PolicyEvaluation(format!(
                        "failed to load policy '{}': {e}",
                        policy.name
                    ))
                })?;
        }
        Ok(engine)
    }
}

impl RbacEngine for RegorusEngine {
    fn evaluate(&self, input: &RbacInput) -> RbacResult<bool> {
        let input_json = serde_json::to_string(input)?;

        let mut engine = self.build_engine()?;

        engine
            .set_input_json(&input_json)
            .map_err(|e| RbacError::Serialization(format!("failed to set RBAC input: {e}")))?;

        let result = engine
            .eval_rule("data.cosmian.kms.rbac.allow".to_owned())
            .map_err(|e| {
                RbacError::PolicyEvaluation(format!(
                    "failed to evaluate RBAC policy rule 'data.cosmian.kms.rbac.allow': {e}"
                ))
            })?;

        let allowed = matches!(result, regorus::Value::Bool(true));
        debug!(
            "RBAC evaluation for user={}, op={}: allowed={}",
            input.subject.user_id, input.action.operation, allowed
        );

        Ok(allowed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::input::{ActionAttrs, EnvironmentAttrs, ResourceAttrs, SubjectAttrs};

    fn make_input(user: &str, roles: &[&str], operation: &str, is_owner: bool) -> RbacInput {
        RbacInput {
            subject: SubjectAttrs {
                user_id: user.to_owned(),
                roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                is_owner,
                is_privileged: false,
            },
            action: ActionAttrs {
                operation: operation.to_owned(),
            },
            resource: ResourceAttrs {
                unique_identifier: Some("key-123".to_owned()),
                object_type: Some("SymmetricKey".to_owned()),
                state: Some("Active".to_owned()),
                owner: Some("owner@example.com".to_owned()),
                sensitive: false,
                extractable: true,
            },
            environment: EnvironmentAttrs::default(),
        }
    }

    #[test]
    fn test_administrator_allows_all() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("admin@example.com", &["administrator"], "encrypt", false);
        assert!(engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_administrator_allows_destroy() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("admin@example.com", &["administrator"], "destroy", false);
        assert!(engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_operator_allows_key_operations() {
        let engine = RegorusEngine::new(None).unwrap();
        for op in &[
            "create", "encrypt", "decrypt", "sign", "get", "import", "export", "locate", "destroy",
        ] {
            let input = make_input("op@example.com", &["operator"], op, false);
            assert!(
                engine.evaluate(&input).unwrap(),
                "operator should be allowed to {op}"
            );
        }
    }

    #[test]
    fn test_auditor_read_only() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("auditor@example.com", &["auditor"], "get", false);
        assert!(engine.evaluate(&input).unwrap());

        let input = make_input("auditor@example.com", &["auditor"], "get_attributes", false);
        assert!(engine.evaluate(&input).unwrap());

        let input = make_input("auditor@example.com", &["auditor"], "encrypt", false);
        assert!(!engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_readonly_minimal() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("reader@example.com", &["readonly"], "get_attributes", false);
        assert!(engine.evaluate(&input).unwrap());

        let input = make_input("reader@example.com", &["readonly"], "locate", false);
        assert!(engine.evaluate(&input).unwrap());

        let input = make_input("reader@example.com", &["readonly"], "get", false);
        assert!(!engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_no_roles_denied() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("nobody@example.com", &[], "get", false);
        assert!(!engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_multiple_roles() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("multi@example.com", &["readonly", "auditor"], "get", false);
        // auditor role grants get
        assert!(engine.evaluate(&input).unwrap());
    }

    #[test]
    fn test_unknown_role_denied() {
        let engine = RegorusEngine::new(None).unwrap();
        let input = make_input("user@example.com", &["custom_role"], "encrypt", false);
        assert!(!engine.evaluate(&input).unwrap());
    }
}
