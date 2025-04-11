use clap::Args;
use serde::{Deserialize, Serialize};

pub const DEFAULT_COSMIAN_UI_DIST_PATH: &str = "/usr/local/cosmian/ui/dist/";

#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct UiConfig {
    /// The UI distribution folder
    #[arg(
        short,
        env = "COSMIAN_UI_DIST_PATH",
        long,
        default_value = DEFAULT_COSMIAN_UI_DIST_PATH
    )]
    pub ui_index_html_folder: String,

    #[clap(flatten)]
    pub ui_oidc_auth: OidcConfig,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            ui_index_html_folder: DEFAULT_COSMIAN_UI_DIST_PATH.to_owned(),
            ui_oidc_auth: OidcConfig::default(),
        }
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
