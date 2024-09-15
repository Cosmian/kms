use std::fmt::{self};

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::{DBConfig, HttpConfig, JwtAuthConfig, WorkspaceConfig};
use crate::telemetry::TelemetryConfig;

const DEFAULT_USERNAME: &str = "admin";

impl Default for ClapConfig {
    fn default() -> Self {
        Self {
            db: DBConfig::default(),
            http: HttpConfig::default(),
            auth: JwtAuthConfig::default(),
            workspace: WorkspaceConfig::default(),
            default_username: DEFAULT_USERNAME.to_owned(),
            force_default_username: false,
            google_cse_kacls_url: None,
            ms_dke_service_url: None,
            telemetry: TelemetryConfig::default(),
            info: false,
        }
    }
}

#[derive(Parser, Serialize, Deserialize)]
#[clap(version, about, long_about = None)]
#[serde(default)]
pub struct ClapConfig {
    #[clap(flatten)]
    pub db: DBConfig,

    #[clap(flatten)]
    pub http: HttpConfig,

    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    /// The default username to use when no authentication method is provided
    #[clap(long, env = "KMS_DEFAULT_USERNAME", default_value = DEFAULT_USERNAME)]
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    #[clap(long, env = "KMS_FORCE_DEFAULT_USERNAME")]
    pub force_default_username: bool,

    /// This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
    ///
    /// It should contain the external URL of this server as configured in Google Workspace client side encryption settings
    /// For instance, if this server is running on domain `cse.my_domain.com`,
    /// the URL should be something like <https://cse.my_domain.com/google_cse>
    #[clap(long, env = "KMS_GOOGLE_CSE_KACLS_URL")]
    pub google_cse_kacls_url: Option<String>,

    /// This setting enables the Microsoft Double Key Encryption service feature of this server.
    ///
    /// It should contain the external URL of this server as configured in Azure App Registrations
    /// as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
    ///
    /// The URL should be something like <https://cse.my_domain.com/ms_dke>
    #[clap(verbatim_doc_comment, long, env = "KMS_MS_DKE_SERVICE_URL")]
    pub ms_dke_service_url: Option<String>,

    #[clap(flatten)]
    pub telemetry: TelemetryConfig,

    /// Print the server configuration information and exit
    #[clap(long, default_value = "false")]
    pub info: bool,
}

impl fmt::Debug for ClapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = x.field("db", &self.db);
        let x = if self.auth.jwt_issuer_uri.is_some() {
            x.field("auth", &self.auth)
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
        let x = x.field(
            "Microsoft Double Key Encryption URL",
            &self.ms_dke_service_url,
        );
        let x = x.field("telemetry", &self.telemetry);
        let x = x.field("info", &self.info);
        x.finish()
    }
}
