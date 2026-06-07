//! OPA (Open Policy Agent) CLI configuration.

use clap::Parser;
use serde::{Deserialize, Serialize};

/// OPA sidecar integration configuration.
#[derive(Parser, Serialize, Deserialize, Clone, Debug, Default)]
pub struct OpaConfig {
    /// OPA sidecar base URL. Setting this enables OPA authorization.
    /// Example: `http://localhost:8181`
    #[clap(long, env = "KMS_OPA_URL")]
    pub opa_url: Option<String>,

    /// OPA evaluation mode: `"exclusive"` (OPA only) or `"enforcing"` (OPA gates access;
    /// for operations on existing objects, a legacy DB grant is also required).
    /// For object-creation operations (`Create`, `CreateKeyPair`, `Import`, `Register`) in
    /// `"enforcing"` mode, OPA's allow decision is sufficient — no DB grant exists yet.
    /// Ignored when `--opa-url` is not set.
    #[clap(long, env = "KMS_OPA_MODE", default_value = "enforcing")]
    pub opa_mode: String,
}
