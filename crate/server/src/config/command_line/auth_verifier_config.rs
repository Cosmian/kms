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
/// # Optional: enable Web UI SAML single sign-on for this realm:
/// auth_verifier_saml_realm           = "kms-saml"
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
    /// When set, the KMS validates bearer tokens and session cookies against the JWKS
    /// published by this server, and checks that the session is still live with
    /// `GET {auth_verifier_url}/whoami` (result cached 30 s). The server must therefore be
    /// reachable at runtime: requests are rejected while it is unreachable.
    /// The `sub` claim is used as the user identity.
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

    /// Auth Verifier realm configured for SAML 2.0 single sign-on in the Web UI.
    ///
    /// When set, the Web UI offers SAML sign-in and the KMS accepts the Auth
    /// Verifier `_ea_` session cookie, but only for tokens issued for this realm.
    /// The Auth Verifier `/saml/` routes must be served from the KMS public origin
    /// (reverse proxy) so the browser sends the cookie to the KMS, and
    /// `kms_public_url` must use `https://`.
    #[clap(long, env = "KMS_AUTH_VERIFIER_SAML_REALM", verbatim_doc_comment)]
    pub auth_verifier_saml_realm: Option<String>,

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

    /// Returns the SAML realm whose `_ea_` session cookies the KMS accepts, or `None`
    /// when SAML single sign-on is disabled (no server URL or no SAML realm).
    #[must_use]
    pub fn saml_session_realm(&self) -> Option<&str> {
        self.auth_verifier_url
            .as_ref()
            .and(self.auth_verifier_saml_realm.as_deref())
    }

    /// Checks the SAML settings: the realm must not be empty or the Auth Verifier admin
    /// realm (`_`), whose password-login sessions would otherwise be accepted as KMS
    /// users, and `auth_verifier_url` must use `https://` because the session cookie, a
    /// bearer credential, is sent to it on logout.
    ///
    /// # Errors
    /// Returns the reason when `auth_verifier_saml_realm` is set and a setting is unsafe.
    pub fn validate_saml(&self) -> Result<(), String> {
        let Some(realm) = self.auth_verifier_saml_realm.as_deref() else {
            return Ok(());
        };
        if realm.trim().is_empty() || realm == "_" {
            return Err(
                "auth_verifier_saml_realm must be a regular realm: not empty and not the admin realm `_`"
                    .to_owned(),
            );
        }
        let https = self
            .auth_verifier_url
            .as_deref()
            .is_some_and(|url| url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "https"));
        if self.auth_verifier_url.is_some() && !https {
            return Err(
                "auth_verifier_saml_realm requires auth_verifier_url to use https://".to_owned(),
            );
        }
        Ok(())
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use super::AuthVerifierConfig;

    fn saml_config(url: &str, realm: &str) -> AuthVerifierConfig {
        AuthVerifierConfig {
            auth_verifier_url: Some(url.to_owned()),
            auth_verifier_saml_realm: Some(realm.to_owned()),
            ..AuthVerifierConfig::default()
        }
    }

    #[test]
    fn test_validate_saml_accepts_https_url_and_regular_realm() {
        assert_eq!(
            saml_config("https://auth.example.com", "kms-saml").validate_saml(),
            Ok(())
        );
        assert_eq!(AuthVerifierConfig::default().validate_saml(), Ok(()));
    }

    #[test]
    fn test_validate_saml_rejects_empty_and_admin_realm() {
        for realm in ["", "  ", "_"] {
            assert!(
                saml_config("https://auth.example.com", realm)
                    .validate_saml()
                    .is_err(),
                "realm {realm:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_validate_saml_rejects_non_https_server_url() {
        for url in ["http://auth.example.com", "auth.example.com", ""] {
            assert!(
                saml_config(url, "kms-saml").validate_saml().is_err(),
                "url {url:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_jwks_uri_default() {
        let cfg = AuthVerifierConfig {
            auth_verifier_url: Some("https://auth.example.com".to_owned()),
            ..AuthVerifierConfig::default()
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
            ..AuthVerifierConfig::default()
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
            ..AuthVerifierConfig::default()
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

    #[test]
    fn test_saml_session_realm_requires_both_url_and_saml_realm() {
        let mut cfg = AuthVerifierConfig {
            auth_verifier_saml_realm: Some("kms-saml".to_owned()),
            ..AuthVerifierConfig::default()
        };
        assert_eq!(cfg.saml_session_realm(), None);

        cfg.auth_verifier_url = Some("https://auth.example.com".to_owned());
        assert_eq!(cfg.saml_session_realm(), Some("kms-saml"));

        cfg.auth_verifier_saml_realm = None;
        cfg.auth_verifier_realm = Some("kms".to_owned());
        assert_eq!(cfg.saml_session_realm(), None);
    }

    /// Verify that the `auth_verifier.toml` test config parses correctly and
    /// enables both bearer-token validation and the Web UI login form.
    #[test]
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
