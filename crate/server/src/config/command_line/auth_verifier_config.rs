use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the Auth Verifier server (server-side).
///
/// When configured, the KMS server validates bearer tokens issued by the Cosmian
/// authentication server.  These tokens use `sub` as the user identity (not `email`)
/// and may not carry a `kid` header field.
///
/// Provide the address of the Auth Verifier server:
/// ```toml
/// [auth_verifier]
/// auth_verifier_url           = "https://localhost:8443"
/// auth_verifier_accept_invalid_certs = false   # set true only for dev/test
/// # Required in addition to the above to enable the Web UI login form:
/// auth_verifier_realm                = "kms"
/// ```
///
/// The JWKS endpoint is derived automatically from `auth_verifier_url` as
/// `{auth_verifier_url}/.well-known/jwks.json` unless overridden via
/// `auth_verifier_jwks_uri`.
#[derive(Args, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthVerifierConfig {
    /// Base URL of the Auth Verifier server (e.g. `https://auth.example.com`).
    ///
    /// When set, the KMS validates bearer tokens against the JWKS published by this
    /// server.  The `sub` claim is used as the user identity.
    #[clap(long, env = "KMS_AUTH_VERIFIER_URL", verbatim_doc_comment)]
    pub auth_verifier_url: Option<String>,

    /// JWKS URI of the Auth Verifier server.
    ///
    /// Defaults to `{auth_verifier_url}/.well-known/jwks.json` when not set.
    #[clap(long, env = "KMS_AUTH_VERIFIER_JWKS_URI", verbatim_doc_comment)]
    pub auth_verifier_jwks_uri: Option<String>,

    /// Realm to authenticate the Web UI against on the Auth Verifier server.
    ///
    /// Required only to enable the Web UI login form for the Auth Verifier
    /// server (`POST /ui/login_as`); bearer-token validation of already-issued tokens
    /// does not need a realm. When unset, the UI falls back to any other configured
    /// authentication method (OIDC/JWT or client certificate).
    #[clap(long, env = "KMS_AUTH_VERIFIER_REALM", verbatim_doc_comment)]
    pub auth_verifier_realm: Option<String>,

    /// Accept invalid or self-signed TLS certificates when fetching the JWKS.
    ///
    /// **Development and testing only.** Never set this in production.
    #[clap(
        long,
        env = "KMS_AUTH_VERIFIER_ACCEPT_INVALID_CERTS",
        default_value = "false",
        verbatim_doc_comment
    )]
    pub auth_verifier_accept_invalid_certs: bool,
}

impl AuthVerifierConfig {
    /// Returns `true` if the Auth Verifier server is configured (i.e. a server URL is set).
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.auth_verifier_url.is_some()
    }

    /// Returns `true` if the Web UI login form for the Auth Verifier server
    /// should be enabled, i.e. both `auth_verifier_url` and `auth_verifier_realm`
    /// are configured.
    #[must_use]
    pub const fn ui_login_enabled(&self) -> bool {
        self.auth_verifier_url.is_some() && self.auth_verifier_realm.is_some()
    }

    /// Returns the effective JWKS URI:
    /// - `auth_verifier_jwks_uri` if explicitly set, or
    /// - `{auth_verifier_url}/.well-known/jwks.json` otherwise.
    ///
    /// Returns `None` when `auth_verifier_url` is not configured.
    #[must_use]
    pub fn jwks_uri(&self) -> Option<String> {
        self.auth_verifier_url.as_ref().map(|url| {
            self.auth_verifier_jwks_uri
                .clone()
                .unwrap_or_else(|| format!("{}/.well-known/jwks.json", url.trim_end_matches('/')))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AuthVerifierConfig;

    #[test]
    fn test_jwks_uri_default() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            auth_verifier_jwks_uri: None,
            auth_verifier_realm: None,
            auth_verifier_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks.json".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_explicit() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            auth_verifier_jwks_uri: Some("https://auth.example.com/custom/jwks".to_owned()),
            auth_verifier_realm: None,
            auth_verifier_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/custom/jwks".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_trailing_slash_stripped() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com/".to_owned()),
            auth_verifier_jwks_uri: None,
            auth_verifier_realm: None,
            auth_verifier_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks.json".to_owned())
        );
    }

    #[test]
    fn test_not_enabled_without_url() {
        let cfg = AuthVerifierConfig::default();
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.jwks_uri(), None);
    }

    #[test]
    fn test_ui_login_enabled_requires_both_url_and_realm() {
        let mut cfg = AuthVerifierConfig::default();
        assert!(!cfg.ui_login_enabled());

        cfg.auth_verifier_url = Some("https://auth.example.com".to_owned());
        assert!(!cfg.ui_login_enabled());

        cfg.auth_verifier_realm = Some("kms".to_owned());
        assert!(cfg.ui_login_enabled());
    }

    /// Verify that the `auth_verifier.toml` test config parses correctly and
    /// enables both bearer-token validation and the Web UI login form.
    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_auth_verifier_toml_config_parses() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_data/configs/server/auth/verifier.toml");
        let toml_content = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;

        // Extract just the [auth_verifier] section and parse it.
        let parsed: toml::Value = toml::from_str(&toml_content)?;

        let auth_section = parsed
            .get("auth_verifier")
            .ok_or("missing [auth_verifier] section")?;

        let cfg: AuthVerifierConfig = auth_section.clone().try_into()?;

        assert!(cfg.is_enabled(), "auth_verifier_url must be set");
        assert!(
            cfg.ui_login_enabled(),
            "both URL and realm must be set for UI login"
        );
        assert_eq!(
            cfg.auth_verifier_url.as_deref(),
            Some("https://localhost:8443")
        );
        assert_eq!(cfg.auth_verifier_realm.as_deref(), Some("_"));
        assert!(cfg.auth_verifier_accept_invalid_certs);
        assert_eq!(
            cfg.jwks_uri().as_deref(),
            Some("https://localhost:8443/.well-known/jwks.json")
        );
        Ok(())
    }
}
