use std::fmt;

use clap::Args;
use serde::{Deserialize, Serialize};

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

#[cfg(target_os = "linux")]
#[must_use]
pub fn get_default_ui_dist_path() -> String {
    "/usr/local/cosmian/ui/dist/".to_owned()
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn get_default_ui_dist_path() -> String {
    "/Applications/Cosmian KMS Server.app/Contents/Resources/ui/".to_owned()
}

#[derive(Default, Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct UiConfig {
    /// The UI distribution folder
    #[arg(short, env = "COSMIAN_UI_DIST_PATH", long)]
    pub ui_index_html_folder: Option<String>,

    #[clap(flatten)]
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

#[derive(Default, Args, Deserialize, Serialize, Clone)]
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

impl fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // if all fields are None, do not debug, return empty
        if self.ui_oidc_client_id.is_none()
            && self.ui_oidc_client_secret.is_none()
            && self.ui_oidc_issuer_url.is_none()
            && self.ui_oidc_logout_url.is_none()
        {
            return Ok(());
        }

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
