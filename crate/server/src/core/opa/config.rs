//! OPA client configuration types.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// The OPA evaluation mode for the KMS permission layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OpaMode {
    /// OPA is not consulted; existing KMS permission logic runs unchanged.
    #[default]
    Disabled,
    /// OPA is the sole decision maker; KMS permission logic is skipped entirely.
    Exclusive,
    /// OPA runs first; if it denies, the request is denied immediately.
    /// If it allows, the KMS permission logic also runs (both must allow).
    Enforcing,
}

impl fmt::Display for OpaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Exclusive => write!(f, "exclusive"),
            Self::Enforcing => write!(f, "enforcing"),
        }
    }
}

impl FromStr for OpaMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(Self::Disabled),
            "exclusive" => Ok(Self::Exclusive),
            "enforcing" => Ok(Self::Enforcing),
            other => Err(format!(
                "invalid OPA mode '{other}': expected 'disabled', 'exclusive', or 'enforcing'"
            )),
        }
    }
}

/// Configuration for the OPA sidecar integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpaParams {
    /// Base URL of the OPA server (e.g. `http://localhost:8181`).
    pub url: String,
    /// Evaluation mode.
    pub mode: OpaMode,
}
