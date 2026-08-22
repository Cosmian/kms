//! OPA (Open Policy Agent) CLI configuration.

use clap::Parser;
use serde::{Deserialize, Serialize};

fn default_opa_mode() -> String {
    "disabled".to_owned()
}

/// OPA sidecar integration configuration.
#[derive(Parser, Serialize, Deserialize, Clone, Debug)]
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
    #[clap(long, env = "KMS_OPA_MODE", default_value = "disabled")]
    #[serde(default = "default_opa_mode")]
    pub opa_mode: String,
}

impl Default for OpaConfig {
    fn default() -> Self {
        Self {
            opa_url: None,
            opa_mode: "disabled".to_owned(),
        }
    }
}
