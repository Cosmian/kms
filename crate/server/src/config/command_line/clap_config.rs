use std::{
    fmt::{self},
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::{
    GoogleCseConfig, HttpConfig, JwtAuthConfig, MainDBConfig, WorkspaceConfig,
    logging::LoggingConfig, ui_config::UiConfig,
};
use crate::{
    config::{ProxyConfig, SocketServerConfig, TlsConfig},
    error::KmsError,
    result::KResult,
};

#[cfg(not(target_os = "windows"))]
const DEFAULT_COSMIAN_KMS_CONF: &str = "/etc/cosmian/kms.toml";
#[cfg(target_os = "windows")]
const DEFAULT_COSMIAN_KMS_CONF: &str = r"C:\ProgramData\Cosmian\kms.toml";

const DEFAULT_USERNAME: &str = "admin";
const HSM_ADMIN: &str = "admin";

impl Default for ClapConfig {
    fn default() -> Self {
        Self {
            db: MainDBConfig::default(),
            socket_server: SocketServerConfig::default(),
            tls: TlsConfig::default(),
            http: HttpConfig::default(),
            proxy: ProxyConfig::default(),
            kms_public_url: None,
            auth: JwtAuthConfig::default(),
            ui_config: UiConfig::default(),
            google_cse_config: GoogleCseConfig::default(),
            workspace: WorkspaceConfig::default(),
            default_username: DEFAULT_USERNAME.to_owned(),
            force_default_username: false,
            ms_dke_service_url: None,
            logging: LoggingConfig::default(),
            info: false,
            hsm_admin: HSM_ADMIN.to_owned(),
            hsm_model: "proteccio".to_owned(),
            hsm_slot: vec![],
            hsm_password: vec![],
            key_encryption_key: None,
            non_revocable_key_id: None,
            privileged_users: None,
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
    pub proxy: ProxyConfig,

    #[clap(flatten)]
    pub auth: JwtAuthConfig,

    #[clap(flatten)]
    pub ui_config: UiConfig,

    #[clap(flatten)]
    pub google_cse_config: GoogleCseConfig,

    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    /// The default username to use when no authentication method is provided
    #[clap(long, env = "KMS_DEFAULT_USERNAME", default_value = DEFAULT_USERNAME)]
    pub default_username: String,

    /// When an authentication method is provided, perform the authentication
    /// but always use the default username instead of the one provided by the authentication method
    #[clap(long, env = "KMS_FORCE_DEFAULT_USERNAME", verbatim_doc_comment)]
    pub force_default_username: bool,

    /// This setting enables the Microsoft Double Key Encryption service feature of this server.
    ///
    /// It should contain the external URL of this server as configured in Azure App Registrations
    /// as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
    ///
    /// The URL should be something like <https://cse.my_domain.com/ms_dke>
    #[clap(verbatim_doc_comment, long, env = "KMS_MS_DKE_SERVICE_URL")]
    pub ms_dke_service_url: Option<String>,

    #[clap(flatten)]
    pub logging: LoggingConfig,

    /// Print the server configuration information and exit
    #[clap(long, default_value = "false")]
    pub info: bool,

    /// The HSM model.
    /// Trustway Proteccio and Utimaco General purpose HSMs are supported.
    #[clap(
        verbatim_doc_comment,
        long,
        value_parser(["proteccio", "utimaco"]),
        default_value = "proteccio"
    )]
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

    /// Force all keys imported or created in the KMS, which are not protected by a key encryption key,
    /// to be wrapped by the specified key encryption key (KEK)
    pub key_encryption_key: Option<String>,

    /// The non-revocable key ID used for demo purposes
    #[clap(long, hide = true)]
    pub non_revocable_key_id: Option<Vec<String>>,

    /// The exposed URL of the KMS - this is required if Google CSE configuration is activated.
    /// If this server is running on the domain `cse.my_domain.com` with this public URL,
    /// The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
    /// The URL is also used during the authentication flow initiated from the KMS UI.
    #[clap(verbatim_doc_comment, long, env = "KMS_PUBLIC_URL")]
    pub kms_public_url: Option<String>,

    /// List of users who have the right to create and import Objects
    /// and grant access rights for Create Kmip Operation.
    #[clap(long, verbatim_doc_comment)]
    pub privileged_users: Option<Vec<String>>,
}

impl ClapConfig {
    /// Load the configuration from the default configuration file
    ///
    /// # Errors
    /// Fails if the configuration file is not found,
    /// or if the configuration file is not valid,
    /// or if the configuration file cannot be read,
    /// or if the configuration file cannot be parsed,
    /// or if the configuration file is not a valid TOML file.
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
                        "WARNING: Configuration file {} not found. Fallback to the default path: \
                         {DEFAULT_COSMIAN_KMS_CONF}",
                        conf_path.display()
                    );
                    // fallback to the default path
                    PathBuf::from(DEFAULT_COSMIAN_KMS_CONF)
                }
            },
        );

        let clap_config = if conf.exists() {
            drop(Self::parse()); // Do that do catch --help or --version even if we use a conf file

            println!(
                "Configuration file {} found. Command line arguments and env variables are \
                 ignored.",
                conf.display()
            );

            let conf_content = std::fs::read_to_string(&conf).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot read KMS server config at: {} - {e:?}",
                    conf.display()
                ))
            })?;
            toml::from_str(&conf_content).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot parse kms server config at: {} - {e:?}",
                    conf.display()
                ))
            })?
        } else {
            println!(
                "WARNING: Configuration file {} not found. Using command line arguments and env \
                 variables.",
                conf.display()
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
        let x = x.field("proxy", &self.proxy);
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
        let x = if self.google_cse_config.google_cse_enable {
            x.field(
                "google_cse_enable",
                &self.google_cse_config.google_cse_enable,
            )
            .field(
                "google_cse_disable_tokens_validation",
                &self.google_cse_config.google_cse_disable_tokens_validation,
            )
            .field(
                "google_cse_incoming_url_whitelist",
                &self.google_cse_config.google_cse_incoming_url_whitelist,
            )
            .field(
                "google_cse_migration_key",
                &self.google_cse_config.google_cse_migration_key,
            )
        } else {
            x.field(
                "google_cse_enable",
                &self.google_cse_config.google_cse_enable,
            )
        };
        let x = x.field(
            "Microsoft Double Key Encryption URL",
            &self.ms_dke_service_url,
        );
        let x = x.field("telemetry", &self.logging);
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
        let x = x.field("key wrapping key", &self.key_encryption_key);
        let x = x.field("non_revocable_key_id", &self.non_revocable_key_id);
        let x = x.field("privileged_users", &self.privileged_users);

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
