use std::{
    fmt::{self},
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::{HttpConfig, JwtAuthConfig, MainDBConfig, WorkspaceConfig, ui_config::UiConfig};
use crate::{
    config::{SocketServerConfig, TlsConfig},
    error::KmsError,
    result::KResult,
    telemetry::TelemetryConfig,
};

const DEFAULT_COSMIAN_KMS_CONF: &str = "/etc/cosmian/kms.toml";
const DEFAULT_USERNAME: &str = "admin";
const HSM_ADMIN: &str = "admin";

impl Default for ClapConfig {
    fn default() -> Self {
        Self {
            db: MainDBConfig::default(),
            socket_server: SocketServerConfig::default(),
            tls: TlsConfig::default(),
            http: HttpConfig::default(),
            kms_public_url: None,
            auth: JwtAuthConfig::default(),
            ui_config: UiConfig::default(),
            workspace: WorkspaceConfig::default(),
            default_username: DEFAULT_USERNAME.to_owned(),
            force_default_username: false,
            google_cse_disable_tokens_validation: false,
            google_cse_kacls_url: None,
            ms_dke_service_url: None,
            telemetry: TelemetryConfig::default(),
            info: false,
            hsm_admin: HSM_ADMIN.to_owned(),
            hsm_model: "proteccio".to_owned(),
            hsm_slot: vec![],
            hsm_password: vec![],
            non_revocable_key_id: None,
        }
    }
}

#[derive(Parser, Serialize, Deserialize)]
#[clap(version, about, long_about = None)]
#[serde(default)]
pub struct ClapConfig {
    #[clap(flatten)]
    pub db: MainDBConfig,

    #[clap(flatten)]
    pub socket_server: SocketServerConfig,

    #[clap(flatten)]
    pub tls: TlsConfig,

    #[clap(flatten)]
    pub http: HttpConfig,

    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap(flatten)]
    pub ui_config: UiConfig,

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

    /// This setting disables the validation of the tokens used by the Google Workspace CSE feature of this server.
    #[clap(
        long,
        requires = "google_cse_kacls_url",
        env = "KMS_GOOGLE_CSE_DISABLE_TOKENS_VALIDATION",
        default_value = "false"
    )]
    pub google_cse_disable_tokens_validation: bool,

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

    /// The HSM model.
    /// Trustway Proteccio and Utimaco General purpose HSMs are supported.
    #[clap(verbatim_doc_comment, long,value_parser(["proteccio", "utimaco"]), default_value = "proteccio")]
    pub hsm_model: String,

    /// The username of the HSM admin.
    /// The HSM admin can create objects on the HSM, destroy them, and potentially export them.
    #[clap(long, env = "KMS_HSM_ADMIN", default_value = HSM_ADMIN)]
    pub hsm_admin: String,

    /// HSM slot number. The slots used must be listed.
    /// Repeat this option to specify multiple slots
    /// while specifying a password for each slot (or an empty string for no password)
    /// e.g.
    /// ```sh
    ///   --hsm_slot 1 --hsm_password password1 \
    ///   --hsm_slot 2 --hsm_password password2
    ///```
    #[clap(verbatim_doc_comment, long)]
    pub hsm_slot: Vec<usize>,

    /// Password for the user logging in to the HSM Slot specified with `--hsm_slot`
    /// Provide an empty string for no password
    /// see `--hsm_slot` for more information
    #[clap(verbatim_doc_comment, long, requires = "hsm_slot")]
    pub hsm_password: Vec<String>,

    /// The non-revocable keys ID used for demo purposes
    #[clap(long, hide = true)]
    pub non_revocable_key_id: Option<Vec<String>>,

    #[clap(verbatim_doc_comment, long, env = "KMS_PUBLIC_URL")]
    pub kms_public_url: Option<String>,
}

impl ClapConfig {
    /// # Errors
    /// Fails if the configuration file is not found or if the configuration file is not valid
    /// or if the configuration file cannot be read
    /// or if the configuration file cannot be parsed
    /// or if the configuration file is not a valid toml file
    #[allow(clippy::print_stdout)] // Logging is not being initialized yet, just use standard prints
    pub fn load_from_file() -> KResult<Self> {
        let conf = std::env::var("COSMIAN_KMS_CONF").map_or_else(
            |_| PathBuf::from(DEFAULT_COSMIAN_KMS_CONF),
            |conf_path| {
                let conf_path = PathBuf::from(conf_path);
                if conf_path.exists() {
                    conf_path
                } else {
                    println!(
                        "WARNING: Configuration file {conf_path:?} not found. Fallback to the \
                         default path: {DEFAULT_COSMIAN_KMS_CONF}"
                    );
                    // fallback to the default path
                    PathBuf::from(DEFAULT_COSMIAN_KMS_CONF)
                }
            },
        );

        let clap_config = if conf.exists() {
            drop(Self::parse()); // Do that do catch --help or --version even if we use a conf file

            println!(
                "Configuration file {conf:?} found. Command line arguments and env variables are \
                 ignored."
            );

            let conf_content = std::fs::read_to_string(&conf).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot read KMS server config at: {conf:?} - {e:?}"
                ))
            })?;
            toml::from_str(&conf_content).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot parse kms server config at: {conf:?} - {e:?}"
                ))
            })?
        } else {
            println!(
                "WARNING: Configuration file {conf:?} not found. Using command line arguments and \
                 env variables."
            );
            Self::parse()
        };

        Ok(clap_config)
    }
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
        let x = x.field("socket server", &self.socket_server);
        let x = x.field("TLS", &self.tls);
        let x = if self.socket_server.socket_server_start {
            x.field("socket server", &self.socket_server)
        } else {
            x
        };
        let x = x.field("ui_index_html_folder", &self.ui_config.ui_index_html_folder);
        let x = if self.ui_config.ui_oidc_auth.ui_oidc_client_id.is_some() {
            x.field("ui_oidc_auth", &self.ui_config.ui_oidc_auth)
        } else {
            x
        };
        let x = x.field("KMS http", &self.http);
        let x = x.field("KMS public URL", &self.kms_public_url);

        let x = x.field("workspace", &self.workspace);
        let x = x.field("default username", &self.default_username);
        let x = x.field("force default username", &self.force_default_username);
        let x = x.field(
            "Google Workspace CSE, disable tokens validation",
            &self.google_cse_disable_tokens_validation,
        );
        let x = x.field(
            "Google Workspace CSE, KACLS URL",
            &self.google_cse_kacls_url,
        );
        let x = x.field(
            "Microsoft Double Key Encryption URL",
            &self.ms_dke_service_url,
        );
        let x = x.field("telemetry", &self.telemetry);
        let x = x.field("info", &self.info);
        let x = x.field("HSM admin username", &self.hsm_admin);
        let x = x.field(
            "hsm_model",
            if self.hsm_slot.is_empty() {
                &"NO HSM"
            } else {
                &self.hsm_model
            },
        );
        let x = x.field("hsm_slots", &self.hsm_slot);
        let x = x.field(
            "hsm_passwords",
            &self
                .hsm_password
                .iter()
                .map(|_| "********")
                .collect::<Vec<&str>>(),
        );
        let x = x.field("non_revocable_key_id", &self.non_revocable_key_id);
        x.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::ClapConfig;

    #[test]
    #[allow(clippy::print_stdout, clippy::unwrap_used)]
    fn test_server_configuration_file() {
        let conf = ClapConfig::default();
        let conf_str = toml::to_string_pretty(&conf).unwrap();
        println!("Pretty TOML print {conf_str}");
    }
}
