use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct OidcConfig {
    /// The client ID of the configured OIDC tenant for UI Auth
    #[clap(long, env = "OIDC_CLIENT_ID")]
    pub client_id: Option<String>,

    /// The client secret of the configured OIDC tenant for UI Auth
    #[clap(long, env = "OIDC_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    /// The issuer URI of the configured OIDC tenant for UI Auth
    #[clap(long, env = "OIDC_ISSUER_URL")]
    pub issuer_url: Option<String>,

    /// The logout URI of the configured OIDC tenant for UI Auth
    #[clap(long, env = "OIDC_LOGOUT_URL")]
    pub logout_url: Option<String>,
}
