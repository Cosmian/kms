use std::path::PathBuf;

use clap::Args;
use serde::{Deserialize, Serialize};

/// RBAC (Role-Based Access Control) configuration.
///
/// When enabled, the KMS enforces role-based access control alongside
/// the existing per-object ACL grants. Access is granted if **either**
/// the RBAC policy **or** the existing ACL allows the operation (OR logic).
///
/// Roles are evaluated using OPA (Open Policy Agent) Rego policies,
/// following the NIST SP 800-162 attribute-based access control model.
#[derive(Args, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RbacConfig {
    /// Path to a Rego (.rego) policy file or directory of Rego files
    /// for RBAC evaluation. Setting this flag enables RBAC enforcement.
    ///
    /// A default policy with four roles (administrator, operator, auditor, readonly)
    /// is shipped at `resources/rbac/default_rbac.rego`.
    #[clap(long, env = "KMS_RBAC_POLICY_PATH", verbatim_doc_comment)]
    pub rbac_policy_path: Option<PathBuf>,

    /// URL of an external OPA server for RBAC policy evaluation.
    /// When set, the KMS forwards authorization decisions to this OPA instance
    /// instead of using the embedded Rego engine.
    ///
    /// Example: `http://localhost:8181`
    ///
    /// The decision endpoint queried is `/v1/data/cosmian/kms/rbac/allow`.
    #[clap(long, env = "KMS_OPA_URL", verbatim_doc_comment)]
    pub opa_url: Option<String>,
}

impl RbacConfig {
    /// Returns `true` if RBAC is enabled (either embedded or external OPA).
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.rbac_policy_path.is_some() || self.opa_url.is_some()
    }
}
