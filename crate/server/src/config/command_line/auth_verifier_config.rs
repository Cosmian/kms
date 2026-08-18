use clap::Args;
use serde::{Deserialize, Deserializer, Serialize, de};

/// Deserialize `auth_verifier_realm` accepting both a single string and a list.
///
/// ```toml
/// auth_verifier_realm = "acme.com"                    # still works
/// auth_verifier_realm = ["acme.com", "partner.com"]   # new multi-realm form
/// ```
fn deserialize_realm_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrList {
        One(String),
        Many(Vec<String>),
    }

    let opt: Option<StringOrList> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(StringOrList::One(s)) if s.is_empty() => {
            Err(de::Error::custom("auth_verifier_realm must not be empty"))
        }
        Some(StringOrList::One(s)) => Ok(Some(vec![s])),
        Some(StringOrList::Many(v)) if v.is_empty() => Err(de::Error::custom(
            "auth_verifier_realm list must not be empty",
        )),
        Some(StringOrList::Many(v)) => Ok(Some(v)),
    }
}

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

    /// Realm(s) to authenticate the Web UI against on the Auth Verifier server.
    ///
    /// Required only to enable the Web UI login form for the Auth Verifier
    /// server (`POST /ui/login_as`); bearer-token validation of already-issued tokens
    /// does not need a realm. When unset, the UI falls back to any other configured
    /// authentication method (OIDC/JWT or client certificate).
    ///
    /// Accepts a single realm name or a list:
    ///
    /// ```toml
    /// auth_verifier_realm = "acme.com"                    # single realm
    /// auth_verifier_realm = ["acme.com", "partner.com"]   # multi-realm
    /// ```
    ///
    /// When multiple realms are configured the Web UI shows a realm selector before
    /// the username/password form.
    #[clap(long, env = "KMS_AUTH_VERIFIER_REALM", verbatim_doc_comment)]
    #[serde(
        default,
        deserialize_with = "deserialize_realm_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_verifier_realm: Option<Vec<String>>,

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
    /// should be enabled, i.e. both `auth_verifier_url` and at least one realm
    /// are configured.
    #[must_use]
    pub fn ui_login_enabled(&self) -> bool {
        self.auth_verifier_url.is_some()
            && self
                .auth_verifier_realm
                .as_ref()
                .is_some_and(|v| !v.is_empty())
    }

    /// Returns the list of configured realms, or an empty slice when none are set.
    #[must_use]
    pub fn realms(&self) -> &[String] {
        self.auth_verifier_realm.as_deref().unwrap_or(&[])
    }

    /// Returns the first configured realm, used as the default when the UI does
    /// not specify one explicitly.
    #[must_use]
    pub fn primary_realm(&self) -> Option<&str> {
        self.auth_verifier_realm
            .as_ref()
            .and_then(|v| v.first().map(String::as_str))
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

        // Single realm via vec
        cfg.auth_verifier_realm = Some(vec!["kms".to_owned()]);
        assert!(cfg.ui_login_enabled());
        assert_eq!(cfg.realms(), &["kms"]);
        assert_eq!(cfg.primary_realm(), Some("kms"));

        // Multiple realms
        cfg.auth_verifier_realm = Some(vec!["acme.com".to_owned(), "partner.com".to_owned()]);
        assert!(cfg.ui_login_enabled());
        assert_eq!(cfg.realms(), &["acme.com", "partner.com"]);
        assert_eq!(cfg.primary_realm(), Some("acme.com"));
    }

    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_realm_deserializes_single_string() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            auth_verifier_url = "https://auth.example.com"
            auth_verifier_realm = "acme.com"
        "#;
        let cfg: AuthVerifierConfig = toml::from_str(toml)?;
        assert_eq!(cfg.realms(), &["acme.com"]);
        assert!(cfg.ui_login_enabled());
        Ok(())
    }

    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_realm_deserializes_list() -> Result<(), Box<dyn std::error::Error>> {
        let toml = r#"
            auth_verifier_url = "https://auth.example.com"
            auth_verifier_realm = ["acme.com", "partner.com"]
        "#;
        let cfg: AuthVerifierConfig = toml::from_str(toml)?;
        assert_eq!(cfg.realms(), &["acme.com", "partner.com"]);
        assert_eq!(cfg.primary_realm(), Some("acme.com"));
        assert!(cfg.ui_login_enabled());
        Ok(())
    }

    /// Verify that the canonical `[auth_verifier]` section parses correctly and
    /// enables both bearer-token validation and the Web UI login form.
    ///
    /// The TOML is inlined here to keep the test self-contained; it mirrors
    /// `test_data/configs/server/auth/auth_verifier.toml` which is in a submodule
    /// not checked out during unit-test CI runs.
    #[test]
    #[allow(clippy::panic_in_result_fn)]
    fn test_auth_verifier_toml_config_parses() -> Result<(), Box<dyn std::error::Error>> {
        let toml_content = r#"
[auth_verifier]
auth_verifier_url = "https://localhost:8443"
auth_verifier_accept_invalid_certs = true
auth_verifier_realm = "_"
"#;

        let parsed: toml::Value = toml::from_str(toml_content)?;
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
        assert_eq!(cfg.primary_realm(), Some("_"));
        assert!(cfg.auth_verifier_accept_invalid_certs);
        assert_eq!(
            cfg.jwks_uri().as_deref(),
            Some("https://localhost:8443/.well-known/jwks.json")
        );
        Ok(())
    }
}
