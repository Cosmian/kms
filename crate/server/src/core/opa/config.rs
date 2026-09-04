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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ── OpaMode::from_str ────────────────────────────────────────────────────

    /// All three valid mode strings parse to the correct variant.
    #[test]
    fn test_opa_mode_from_str_all_valid_values() {
        assert_eq!("disabled".parse::<OpaMode>().unwrap(), OpaMode::Disabled);
        assert_eq!("exclusive".parse::<OpaMode>().unwrap(), OpaMode::Exclusive);
        assert_eq!("enforcing".parse::<OpaMode>().unwrap(), OpaMode::Enforcing);
    }

    /// Parsing is case-insensitive (`"EXCLUSIVE"`, `"Enforcing"` etc. are accepted).
    #[test]
    fn test_opa_mode_from_str_case_insensitive() {
        assert_eq!("DISABLED".parse::<OpaMode>().unwrap(), OpaMode::Disabled);
        assert_eq!("EXCLUSIVE".parse::<OpaMode>().unwrap(), OpaMode::Exclusive);
        assert_eq!("Enforcing".parse::<OpaMode>().unwrap(), OpaMode::Enforcing);
    }

    /// An unrecognised string returns an `Err` with a helpful message.
    #[test]
    fn test_opa_mode_from_str_invalid_returns_error() {
        let err = "permissive".parse::<OpaMode>().unwrap_err();
        assert!(
            err.contains("invalid OPA mode"),
            "error message should mention 'invalid OPA mode', got: {err}"
        );
        assert!(err.contains("permissive"));
    }

    // ── OpaMode::Display ─────────────────────────────────────────────────────

    /// Each variant formats to the expected lowercase string used in config and logs.
    #[test]
    fn test_opa_mode_display() {
        assert_eq!(OpaMode::Disabled.to_string(), "disabled");
        assert_eq!(OpaMode::Exclusive.to_string(), "exclusive");
        assert_eq!(OpaMode::Enforcing.to_string(), "enforcing");
    }

    // ── OpaMode::Default ─────────────────────────────────────────────────────

    /// `OpaMode::default()` must be `Disabled` so that servers without OPA config
    /// behave identically to pre-OPA deployments (backward-compatibility invariant).
    #[test]
    fn test_opa_mode_default_is_disabled() {
        assert_eq!(OpaMode::default(), OpaMode::Disabled);
    }

    // ── round-trip ───────────────────────────────────────────────────────────

    /// `Display` → `from_str` round-trip is identity for every variant.
    #[test]
    fn test_opa_mode_display_from_str_round_trip() {
        for mode in [OpaMode::Disabled, OpaMode::Exclusive, OpaMode::Enforcing] {
            let s = mode.to_string();
            let parsed: OpaMode = s.parse().expect("round-trip parse must succeed");
            assert_eq!(parsed, mode, "round-trip failed for {mode}");
        }
    }
}
