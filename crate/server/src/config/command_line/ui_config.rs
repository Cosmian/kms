// `collection_is_never_read`: the `ConfigArgs` derive generates intermediate
// Vec collections used only as building blocks in the arg-merge logic; clippy
// cannot see through the macro boundary.
// `struct_field_names`: `ui_oidc_*` fields share a prefix because they are
// flattened into the CLI namespace and serde keys.
#![allow(clippy::collection_is_never_read, clippy::struct_field_names)]

use std::{fmt, sync::Arc};

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

/// Default UI distribution folder path on Linux.
#[cfg(target_os = "linux")]
const LINUX_UI_DIST_PATH: &str = "/usr/local/cosmian/ui/dist/";

#[cfg(target_os = "windows")]
#[must_use]
pub fn get_default_ui_dist_path() -> String {
    if let Some(path) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("ui")))
    {
        if path.join("index.html").exists() {
            return path.to_string_lossy().into_owned();
        }
    }
    std::env::var("LOCALAPPDATA").map_or_else(
        |_| String::from("C:\\ProgramData\\cosmian\\ui"),
        |localappdata| format!("{localappdata}\\Cosmian KMS Server\\ui"),
    )
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn get_default_ui_dist_path() -> String {
    LINUX_UI_DIST_PATH.to_owned()
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn get_default_ui_dist_path() -> String {
    "/Applications/Cosmian KMS Server.app/Contents/Resources/ui/".to_owned()
}

#[derive(Default, Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Disable the embedded web UI. When set to false, the UI HTML assets are
    /// not served and all `/ui/` routes return 404.
    #[arg(long, env = "KMS_UI_ENABLE", default_value = "true")]
    #[serde(default = "default_true")]
    pub enable: bool,

    /// The UI distribution folder
    #[arg(short, env = "COSMIAN_UI_DIST_PATH", long)]
    pub ui_index_html_folder: Option<String>,

    /// A secret salt used to derive the session cookie encryption key.
    /// This MUST be identical across all KMS instances behind the same load balancer.
    /// This should only be provided when `ui_index_html_folder` is explicitly defined.
    #[clap(verbatim_doc_comment, long, env = "KMS_SESSION_SALT")]
    pub ui_session_salt: Option<String>,

    // `#[config(no_flatten)]` tells `clap_config_fallback` NOT to flatten this
    // nested struct into the parent TOML table: the KMS config file must use a
    // `[ui_config.ui_oidc_auth]` sub-table.
    // `#[command(flatten)]` is a clap directive that inlines CLI flags from
    // `OidcConfig` into the parent struct; it is unrelated to TOML layout.
    // The two attributes operate at different layers (config file vs CLI) and
    // are intentionally used together.
    #[config(no_flatten)]
    #[command(flatten)]
    pub ui_oidc_auth: OidcConfig,
}

impl UiConfig {
    /// Get the UI distribution folder path, resolving the default if not set
    pub fn get_ui_index_html_folder(&self) -> String {
        self.ui_index_html_folder
            .clone()
            .unwrap_or_else(get_default_ui_dist_path)
    }
}

const fn default_true() -> bool {
    true
}

#[derive(Default, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct OidcConfig {
    /// The client ID of the configured OIDC tenant for UI Auth
    #[clap(long, env = "UI_OIDC_CLIENT_ID")]
    pub ui_oidc_client_id: Option<String>,

    /// The client secret of the configured OIDC tenant for UI Auth
    #[clap(long, env = "UI_OIDC_CLIENT_SECRET")]
    pub ui_oidc_client_secret: Option<String>,

    /// The issuer URI of the configured OIDC tenant for UI Auth
    #[clap(long, env = "UI_OIDC_ISSUER_URL")]
    pub ui_oidc_issuer_url: Option<String>,

    /// The logout URI of the configured OIDC tenant for UI Auth
    #[clap(long, env = "UI_OIDC_LOGOUT_URL")]
    pub ui_oidc_logout_url: Option<String>,
}

/// OIDC endpoints discovered at server startup from the `IdP`'s
/// `.well-known/openid-configuration` document.
///
/// WARNING: `authorization_endpoint` and `token_endpoint` are cached at startup.
/// Changes to the `IdP` configuration (issuer URL, endpoint URLs) require a
/// **server restart** to take effect. The signing keys held by `jwks_manager`
/// are *not* frozen at startup: the UI OIDC callback refreshes them on demand
/// (refresh-on-miss) whenever an unknown `kid` is encountered, so `IdP` signing
/// key rotation does **not** require a restart.
#[derive(Clone, Debug)]
pub struct OidcDiscoveredEndpoints {
    /// The `IdP`'s authorization endpoint URL.
    pub authorization_endpoint: String,
    /// The `IdP`'s token exchange endpoint URL.
    pub token_endpoint: String,
    /// The `JwksManager` pre-loaded with the `IdP`'s signing keys. Refreshed
    /// on demand (refresh-on-miss) when the UI OIDC callback encounters an
    /// unknown `kid`; see `crate::routes::ui_auth::callback`.
    pub jwks_manager: Arc<crate::middlewares::JwksManager>,
}

/// Runtime OIDC configuration combining the static `OidcConfig` with endpoints
/// discovered from the `IdP` at startup.
#[derive(Clone, Debug)]
pub struct OidcRuntimeConfig {
    /// The static OIDC configuration (client ID, secret, issuer URL, logout URL).
    pub config: OidcConfig,
    /// Populated when `ui_oidc_issuer_url` is configured; `None` otherwise.
    pub discovered: Option<OidcDiscoveredEndpoints>,
}

/// Runtime configuration for the Web UI's Cosmian authentication server (BFF) login.
///
/// Injected as `app_data` on the `/ui` scope so `crate::routes::ui_auth::login_as` can
/// proxy the browser's username/password (+ optional TOTP) login to the configured
/// Cosmian authentication server and validate the JWT it returns.
///
/// `jwks_manager` is the *same* manager built for the bearer-token `CosmianAuthServer`
/// middleware (see `prepare_kms_server`) — no second JWKS fetch is performed.
#[derive(Clone, Debug)]
pub struct CosmianAuthRuntimeConfig {
    /// The static Cosmian auth configuration (server URL, realm, TLS options).
    pub config: crate::config::CosmianAuthServerConfig,
    /// `Some` when the Cosmian auth server is configured; `None` otherwise, in which
    /// case `login_as` responds with an error indicating it is not configured.
    pub jwks_manager: Option<Arc<crate::middlewares::JwksManager>>,
}

impl fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("OidcConfig");

        if let Some(ui_oidc_client_id) = &self.ui_oidc_client_id {
            debug_struct.field("ui_oidc_client_id", ui_oidc_client_id);
        }
        if self.ui_oidc_client_secret.is_some() {
            debug_struct.field("ui_oidc_client_secret", &"****");
        }
        if let Some(ui_oidc_issuer_url) = &self.ui_oidc_issuer_url {
            debug_struct.field("ui_oidc_issuer_url", ui_oidc_issuer_url);
        }
        if let Some(ui_oidc_logout_url) = &self.ui_oidc_logout_url {
            debug_struct.field("ui_oidc_logout_url", ui_oidc_logout_url);
        }

        debug_struct.finish()
    }
}
