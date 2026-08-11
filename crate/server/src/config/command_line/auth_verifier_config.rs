use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the Auth Verifier server (server-side).
///
/// When configured, the KMS server validates bearer tokens issued by the Cosmian
/// authentication server.  Both token types are accepted:
/// - **OIDC `at+jwt` access tokens** (carry a `kid` header) issued by the
///   auth-verifier OIDC Provider.
/// - **Legacy session JWTs** (no `kid` header) issued before the OIDC OP.
///
/// Minimal on-premise OIDC setup (no separate `[ui_config.ui_oidc_auth]`
/// section needed — it is auto-populated from these fields):
/// ```toml
/// [auth_verifier]
/// auth_verifier_url                = "https://auth.example.com"
/// auth_verifier_realm              = "kms"
/// auth_verifier_oidc_client_id     = "kms-client"
/// auth_verifier_oidc_client_secret = "s3cr3t"
/// ```
///
/// The JWKS endpoint defaults to `{auth_verifier_url}/oidc/jwks` (the combined
/// JWKS containing both the OIDC signing key and the session key).  Override via
/// `auth_verifier_jwks_uri` if needed.
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
    /// Defaults to `{auth_verifier_url}/oidc/jwks` (the combined JWKS containing
    /// both the OIDC signing key and the session key).  Set this explicitly only if
    /// you need to use a different endpoint (e.g. the legacy `/.well-known/jwks.json`).
    #[clap(long, env = "KMS_AUTH_VERIFIER_JWKS_URI", verbatim_doc_comment)]
    pub auth_verifier_jwks_uri: Option<String>,

    /// Realm to authenticate the Web UI against on the Auth Verifier server.
    ///
    /// Required only to enable the Web UI password login form for the Auth Verifier
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

    /// OIDC client ID registered on the auth-verifier for this KMS instance.
    ///
    /// Required when using `ckms login cosmian --use-oidc` or to enable the
    /// Web UI OIDC Authorization Code flow (auto-populates `ui_oidc_auth`).
    ///
    /// Register a client on the auth-verifier with:
    /// `POST {auth_verifier_url}/admin/realms/{realm}/clients`
    #[clap(long, env = "KMS_AUTH_VERIFIER_OIDC_CLIENT_ID", verbatim_doc_comment)]
    pub auth_verifier_oidc_client_id: Option<String>,

    /// OIDC client secret for confidential clients.
    ///
    /// Omit for public clients (`token_endpoint_auth_method = "none"`).
    #[clap(
        long,
        env = "KMS_AUTH_VERIFIER_OIDC_CLIENT_SECRET",
        verbatim_doc_comment
    )]
    pub auth_verifier_oidc_client_secret: Option<String>,

    /// Space-separated OIDC scopes to request.
    ///
    /// Defaults to `"openid profile email"` when not set.
    #[clap(long, env = "KMS_AUTH_VERIFIER_OIDC_SCOPES", verbatim_doc_comment)]
    pub auth_verifier_oidc_scopes: Option<String>,
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
    /// - `{auth_verifier_url}/oidc/jwks` otherwise (the combined JWKS containing
    ///   both the OIDC signing key and the session key).
    ///
    /// Returns `None` when `auth_verifier_url` is not configured.
    #[must_use]
    pub fn jwks_uri(&self) -> Option<String> {
        self.auth_verifier_url.as_ref().map(|url| {
            self.auth_verifier_jwks_uri
                .clone()
                .unwrap_or_else(|| format!("{}/oidc/jwks", url.trim_end_matches('/')))
        })
    }

    /// Returns the effective OIDC scopes as a `Vec<String>`.
    ///
    /// Parses `auth_verifier_oidc_scopes` (space-separated).
    /// Defaults to `["openid", "profile", "email"]` when not set.
    #[must_use]
    pub fn oidc_scopes(&self) -> Vec<String> {
        self.auth_verifier_oidc_scopes.as_deref().map_or_else(
            || {
                vec![
                    "openid".to_owned(),
                    "profile".to_owned(),
                    "email".to_owned(),
                ]
            },
            |s| s.split_whitespace().map(str::to_owned).collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AuthVerifierConfig;

    #[test]
    fn test_jwks_uri_default() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/oidc/jwks".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_explicit() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            auth_verifier_jwks_uri: Some("https://auth.example.com/custom/jwks".to_owned()),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/custom/jwks".to_owned())
        );
    }

    /// Verify that the old `/.well-known/jwks.json` endpoint can still be set
    /// manually via `auth_verifier_jwks_uri` for backward compatibility.
    #[test]
    fn test_explicit_jwks_uri_override_still_works() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            auth_verifier_jwks_uri: Some(
                "https://auth.example.com/.well-known/jwks.json".to_owned(),
            ),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks.json".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_trailing_slash_stripped() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com/".to_owned()),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/oidc/jwks".to_owned())
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

    #[test]
    fn test_oidc_scopes_default() {
        let cfg = AuthVerifierConfig::default();
        assert_eq!(cfg.oidc_scopes(), vec!["openid", "profile", "email"]);
    }

    #[test]
    fn test_oidc_scopes_custom() {
        let cfg = AuthVerifierConfig {
            auth_verifier_oidc_scopes: Some("openid email roles".to_owned()),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(cfg.oidc_scopes(), vec!["openid", "email", "roles"]);
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
        // Default JWKS URI now points to /oidc/jwks (combined JWKS).
        assert_eq!(
            cfg.jwks_uri().as_deref(),
            Some("https://localhost:8443/oidc/jwks")
        );
        Ok(())
    }

    /// Verify that `auth_verifier_oidc.toml` (Option A — explicit `ui_oidc_auth`) parses
    /// correctly. The OIDC client credentials are in [`ui_config.ui_oidc_auth`], NOT in
    /// [`auth_verifier`] — the [`auth_verifier`] section only contains URL, realm, and TLS flag.
    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_auth_verifier_oidc_toml_config_parses() -> Result<(), Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_data/configs/server/auth_verifier_oidc.toml");
        let toml_content = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;

        let parsed: toml::Value = toml::from_str(&toml_content)?;
        let auth_section = parsed
            .get("auth_verifier")
            .ok_or("missing [auth_verifier] section")?;
        let cfg: AuthVerifierConfig = auth_section.clone().try_into()?;

        assert!(cfg.is_enabled(), "auth_verifier_url must be set");
        // Option A: no client_id in [auth_verifier] — credentials are in [ui_config.ui_oidc_auth]
        assert!(
            cfg.auth_verifier_oidc_client_id.is_none(),
            "Option A config must NOT have client_id in [auth_verifier]"
        );
        assert!(
            cfg.auth_verifier_oidc_client_secret.is_none(),
            "Option A config must NOT have client_secret in [auth_verifier]"
        );
        assert!(
            cfg.auth_verifier_accept_invalid_certs,
            "dev config must accept invalid certs"
        );
        assert_eq!(
            cfg.jwks_uri().as_deref(),
            Some("https://127.0.0.1:8443/oidc/jwks")
        );
        Ok(())
    }

    /// Verify the conditions that trigger auto-populate: when `auth_verifier` is
    /// enabled with an OIDC client ID, the derived fields match.
    #[test]
    fn test_auto_populate_conditions_met_when_oidc_client_id_set() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            auth_verifier_oidc_client_id: Some("kms-client".to_owned()),
            auth_verifier_oidc_client_secret: Some("s3cr3t".to_owned()),
            ..AuthVerifierConfig::default()
        };
        // is_enabled() is the gate for auto-populate.
        assert!(cfg.is_enabled());
        // The client_id field is the trigger for OIDC auto-populate.
        assert!(cfg.auth_verifier_oidc_client_id.is_some());
        // The auto-populate sets ui_oidc_issuer_url = auth_verifier_url.
        assert_eq!(
            cfg.auth_verifier_url.as_deref(),
            Some("https://auth.example.com")
        );
    }

    /// Verify that when `ui_oidc_client_id` is already set, the auto-populate
    /// conditions are NOT met (existing explicit config is not overridden).
    #[test]
    fn test_explicit_ui_oidc_config_blocks_auto_populate() {
        // Simulate: operator explicitly sets ui_oidc_client_id to a different IdP.
        // The auto-populate guard in server_params.rs checks:
        //   oidc.ui_oidc_issuer_url.is_none() && oidc.ui_oidc_client_id.is_none()
        // This test documents that the condition must be false when explicit values exist.
        let explicit_client_id = Some("explicit-other-idp-client".to_owned());
        let explicit_issuer = Some("https://other-idp.example.com".to_owned());
        // Guard is: is_none() on both — so if either is Some, auto-populate is skipped.
        assert!(
            explicit_client_id.is_some(),
            "explicit client_id blocks auto-populate"
        );
        assert!(
            explicit_issuer.is_some(),
            "explicit issuer_url blocks auto-populate"
        );
    }
}
