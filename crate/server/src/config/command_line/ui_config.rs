use clap::Args;
use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "windows"))]
pub const DEFAULT_COSMIAN_UI_DIST_PATH: &str = "/usr/local/cosmian/ui/dist/";

// On Windows, we need to resolve %LOCALAPPDATA% at runtime
#[cfg(target_os = "windows")]
pub fn get_default_ui_dist_path() -> String {
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        format!("{}\\Cosmian KMS Server\\ui", localappdata)
    } else {
        // Fallback if LOCALAPPDATA is not set (shouldn't happen on Windows)
        String::from("C:\\ProgramData\\cosmian\\ui")
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_default_ui_dist_path() -> String {
    DEFAULT_COSMIAN_UI_DIST_PATH.to_string()
}

#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct UiConfig {
    /// The UI distribution folder
    #[arg(short, env = "COSMIAN_UI_DIST_PATH", long)]
    pub ui_index_html_folder: Option<String>,

    #[clap(flatten)]
    pub ui_oidc_auth: OidcConfig,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            ui_index_html_folder: None,
            ui_oidc_auth: OidcConfig::default(),
        }
    }
}

impl UiConfig {
    /// Get the UI distribution folder path, resolving the default if not set
    pub fn get_ui_index_html_folder(&self) -> String {
        self.ui_index_html_folder
            .clone()
            .unwrap_or_else(get_default_ui_dist_path)
    }
}

#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
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
