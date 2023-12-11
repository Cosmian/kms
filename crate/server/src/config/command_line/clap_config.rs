use std::fmt::{self};

use clap::Parser;
use tee_attestation::is_running_inside_tee;

use super::{
    BootstrapServerConfig, DBConfig, HttpConfig, HttpsCertbotConfig, JWEConfig, JwtAuthConfig,
    TeeConfig, WorkspaceConfig,
};

#[derive(Parser, Default)]
#[clap(version, about, long_about = None)]
pub struct ClapConfig {
    #[clap(flatten)]
    pub db: DBConfig,

    #[clap(flatten)]
    pub http: HttpConfig,

    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap(flatten)]
    pub bootstrap_server: BootstrapServerConfig,

    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    #[clap(flatten)]
    pub certbot_https: HttpsCertbotConfig,

    /// The default username to use when no authentication method is provided
    #[clap(long, env = "KMS_DEFAULT_USERNAME", default_value = "admin")]
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    #[clap(long, env = "KMS_FORCE_DEFAULT_USERNAME", default_value = "false")]
    pub force_default_username: bool,

    #[clap(flatten)]
    pub jwe: JWEConfig,

    #[clap(flatten)]
    pub tee: TeeConfig,

    #[clap(long, env = "KMS_GOOGLE_CSE_KACLS_URL")]
    /// This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
    ///
    /// It should contain the external URL of this server as configured in Google Workspace client side encryption settings
    /// For instance, if this server is running on domain `cse.my_domain.com`,
    /// the URL should be something like <https://cse.my_domain.com/google_cse>
    pub google_cse_kacls_url: Option<String>,
}

impl fmt::Debug for ClapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = if self.bootstrap_server.use_bootstrap_server {
            x.field(
                "bootstrap server port",
                &self.bootstrap_server.bootstrap_server_port,
            )
            .field(
                "bootstrap server subject",
                &self.bootstrap_server.bootstrap_server_subject,
            )
            .field(
                "bootstrap server days before expiration",
                &self.bootstrap_server.bootstrap_server_expiration_days,
            )
        } else {
            &mut x
        };
        let x = x.field("db", &self.db);
        let x = if self.auth.jwt_issuer_uri.is_some() {
            x.field("auth0", &self.auth)
        } else {
            x
        };
        let x = if is_running_inside_tee() {
            x.field("tee", &self.tee)
        } else {
            x
        };
        let x = x.field("KMS http", &self.http);
        let x = if self.certbot_https.use_certbot {
            x.field("certbot", &self.certbot_https)
        } else {
            x
        };
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
