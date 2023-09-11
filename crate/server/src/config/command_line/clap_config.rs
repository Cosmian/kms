use std::fmt::{self};

use clap::Parser;
use libsgx::utils::is_running_inside_enclave;

use super::{
    BootstrapServerConfig, DBConfig, EnclaveConfig, HttpConfig, HttpsCertbotConfig, JWEConfig,
    JwtAuthConfig, WorkspaceConfig,
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
    pub enclave: EnclaveConfig,
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
                "bootstrap server CN",
                &self.bootstrap_server.bootstrap_server_common_name,
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
        let x = if is_running_inside_enclave() {
            x.field("enclave", &self.enclave)
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
        x.finish()
    }
}
