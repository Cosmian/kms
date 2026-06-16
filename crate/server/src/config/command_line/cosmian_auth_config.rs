use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the Cosmian authentication server (server-side).
///
/// When configured, the KMS server validates bearer tokens issued by the Cosmian
/// authentication server.  These tokens use `sub` as the user identity (not `email`)
/// and may not carry a `kid` header field.
///
/// Provide the address of the Cosmian auth server:
/// ```toml
/// [cosmian_auth]
/// server_url            = "https://localhost:8443"
/// accept_invalid_certs  = false   # set true only for dev/test
/// ```
///
/// The JWKS endpoint is derived automatically from `server_url` as
/// `{server_url}/.well-known/jwks.json` unless overridden via `jwks_uri`.
#[derive(Args, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CosmianAuthConfig {
    /// Base URL of the Cosmian authentication server (e.g. `https://auth.example.com`).
    ///
    /// When set, the KMS validates bearer tokens against the JWKS published by this
    /// server.  The `sub` claim is used as the user identity.
    #[clap(long, env = "KMS_COSMIAN_AUTH_SERVER_URL", verbatim_doc_comment)]
    pub cosmian_auth_server_url: Option<String>,

    /// JWKS URI of the Cosmian authentication server.
    ///
    /// Defaults to `{cosmian_auth_server_url}/.well-known/jwks.json` when not set.
    #[clap(long, env = "KMS_COSMIAN_AUTH_JWKS_URI", verbatim_doc_comment)]
    pub cosmian_auth_jwks_uri: Option<String>,

    /// Accept invalid or self-signed TLS certificates when fetching the JWKS.
    ///
    /// **Development and testing only.** Never set this in production.
    #[clap(long, env = "KMS_COSMIAN_AUTH_ACCEPT_INVALID_CERTS", default_value = "false", verbatim_doc_comment)]
    pub cosmian_auth_accept_invalid_certs: bool,
}

impl CosmianAuthConfig {
    /// Returns `true` if the Cosmian auth server is configured (i.e. a server URL is set).
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.cosmian_auth_server_url.is_some()
    }

    /// Returns the effective JWKS URI:
    /// - `cosmian_auth_jwks_uri` if explicitly set, or
    /// - `{cosmian_auth_server_url}/.well-known/jwks.json` otherwise.
    ///
    /// Returns `None` when `cosmian_auth_server_url` is not configured.
    #[must_use]
    pub fn jwks_uri(&self) -> Option<String> {
        self.cosmian_auth_server_url.as_ref().map(|url| {
            self.cosmian_auth_jwks_uri.clone().unwrap_or_else(|| {
                format!("{}/.well-known/jwks.json", url.trim_end_matches('/'))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CosmianAuthConfig;

    #[test]
    fn test_jwks_uri_default() {
        let cfg = CosmianAuthConfig {
            cosmian_auth_server_url: Some("https://auth.example.com".to_owned()),
            cosmian_auth_jwks_uri: None,
            cosmian_auth_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks.json".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_explicit() {
        let cfg = CosmianAuthConfig {
            cosmian_auth_server_url: Some("https://auth.example.com".to_owned()),
            cosmian_auth_jwks_uri: Some("https://auth.example.com/custom/jwks".to_owned()),
            cosmian_auth_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/custom/jwks".to_owned())
        );
    }

    #[test]
    fn test_jwks_uri_trailing_slash_stripped() {
        let cfg = CosmianAuthConfig {
            cosmian_auth_server_url: Some("https://auth.example.com/".to_owned()),
            cosmian_auth_jwks_uri: None,
            cosmian_auth_accept_invalid_certs: false,
        };
        assert_eq!(
            cfg.jwks_uri(),
            Some("https://auth.example.com/.well-known/jwks.json".to_owned())
        );
    }

    #[test]
    fn test_not_enabled_without_url() {
        let cfg = CosmianAuthConfig::default();
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.jwks_uri(), None);
    }
}
