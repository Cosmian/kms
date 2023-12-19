use std::fmt::{self};

use clap::Parser;
use clap_serde_derive::ClapSerde;
use serde::Serialize;

use super::{DBConfig, HttpConfig, JWEConfig, JwtAuthConfig, WorkspaceConfig};

#[derive(Parser, /*Default,*/ ClapSerde, Serialize)]
#[clap(version, about, long_about = None)]
pub struct ClapConfig {
    #[clap_serde]
    #[clap(flatten)]
    pub db: DBConfig,

    #[clap_serde]
    #[clap(flatten)]
    pub http: HttpConfig,

    #[clap_serde]
    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap_serde]
    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    /// The default username to use when no authentication method is provided
    #[default("admin".to_string())]
    #[clap(long, env = "KMS_DEFAULT_USERNAME")]
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    #[clap(long, env = "KMS_FORCE_DEFAULT_USERNAME")]
    pub force_default_username: bool,

    #[clap_serde]
    #[clap(flatten)]
    pub jwe: JWEConfig,

    /// This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
    ///
    /// It should contain the external URL of this server as configured in Google Workspace client side encryption settings
    /// For instance, if this server is running on domain `cse.my_domain.com`,
    /// the URL should be something like <https://cse.my_domain.com/google_cse>
    #[clap(long, env = "KMS_GOOGLE_CSE_KACLS_URL")]
    pub google_cse_kacls_url: Option<String>,
}

impl fmt::Debug for ClapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = x.field("db", &self.db);
        let x = if self.auth.jwt_issuer_uri.is_some() {
            x.field("auth0", &self.auth)
        } else {
            x
        };
        let x = x.field("KMS http", &self.http);
        let x = x.field("workspace", &self.workspace);
        let x = x.field("default username", &self.default_username);
        let x = x.field("force default username", &self.force_default_username);
        let x = x.field(
            "Google Workspace CSE, KACLS Url",
            &self.google_cse_kacls_url,
        );
        x.finish()
    }
}
