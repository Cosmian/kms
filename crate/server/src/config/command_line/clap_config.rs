use std::{
    fmt::{self},
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::{
    GoogleCseConfig, HsmConfig, HttpConfig, IdpAuthConfig, MainDBConfig, WorkspaceConfig,
    logging::LoggingConfig, ui_config::UiConfig,
};
use crate::{
    config::{ProxyConfig, SocketServerConfig, TlsConfig},
    error::KmsError,
    result::KResult,
};

#[cfg(not(target_os = "windows"))]
const DEFAULT_COSMIAN_KMS_CONF: &str = "/etc/cosmian/kms.toml";

// On Windows, we need to resolve %LOCALAPPDATA% at runtime
#[cfg(target_os = "windows")]
fn get_default_config_path() -> String {
    std::env::var("LOCALAPPDATA").map_or_else(
        |_| String::from("C:\\ProgramData\\cosmian\\kms.toml"),
        |localappdata| format!("{localappdata}\\Cosmian KMS Server\\kms.toml"),
    )
}

#[cfg(not(target_os = "windows"))]
fn get_default_config_path() -> String {
    DEFAULT_COSMIAN_KMS_CONF.to_owned()
}

const DEFAULT_USERNAME: &str = "admin";

impl Default for ClapConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            db: MainDBConfig::default(),
            socket_server: SocketServerConfig::default(),
            tls: TlsConfig::default(),
            http: HttpConfig::default(),
            proxy: ProxyConfig::default(),
            kms_public_url: None,
            idp_auth: IdpAuthConfig::default(),
            ui_config: UiConfig::default(),
            google_cse_config: GoogleCseConfig::default(),
            workspace: WorkspaceConfig::default(),
            default_username: DEFAULT_USERNAME.to_owned(),
            force_default_username: false,
            ms_dke_service_url: None,
            logging: LoggingConfig::default(),
            info: false,
            hsm: HsmConfig::default(),
            key_encryption_key: None,
            default_unwrap_type: None,
            non_revocable_key_id: None,
            privileged_users: None,
        }
    }
}

#[derive(Parser, Serialize, Deserialize)]
#[clap(version, about, long_about = None)]
#[serde(default)]
pub struct ClapConfig {
    /// Explicit configuration file path provided via -c / --config.
    /// When set, this file takes precedence over the `COSMIAN_KMS_CONF` environment variable
    /// and the default system path. All other command line arguments (except `--help` / `--version`)
    /// and environment variables are ignored once the configuration file is loaded.
    #[clap(short = 'c', long = "config", value_name = "COSMIAN_KMS_CONF")]
    pub config_path: Option<PathBuf>,

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

    /// Print the server configuration information and exit
    #[clap(long, default_value = "false")]
    pub info: bool,

    #[clap(flatten)]
    #[serde(flatten)]
    pub hsm: HsmConfig,

    /// Force all keys imported or created in the KMS, which are not protected by a key encryption key,
    /// to be wrapped by the specified key encryption key (KEK)
    pub key_encryption_key: Option<String>,

    /// Specifies which KMIP object types should be automatically unwrapped when retrieved.
    /// Repeat this option to specify multiple object types
    /// e.g.
    /// ```sh
    ///   --default-unwrap-type SecretData \
    ///   --default-unwrap-type SymmetricKey
    /// ```
    #[clap(verbatim_doc_comment,
        long,
        value_parser(["All", "Certificate", "CertificateRequest", "OpaqueObject", "PGPKey", "PrivateKey", "PublicKey", "SecretData", "SplitKey", "SymmetricKey"])
    )]
    pub default_unwrap_type: Option<Vec<String>>,

    /// The exposed URL of the KMS - this is required if Google CSE configuration is activated.
    /// If this server is running on the domain `cse.my_domain.com` with this public URL,
    /// The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
    /// The URL is also used during the authentication flow initiated from the KMS UI.
    #[clap(verbatim_doc_comment, long, env = "KMS_PUBLIC_URL")]
    pub kms_public_url: Option<String>,

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
    pub idp_auth: IdpAuthConfig,

    #[clap(flatten)]
    pub ui_config: UiConfig,

    #[clap(flatten)]
    pub google_cse_config: GoogleCseConfig,

    #[clap(flatten)]
    pub workspace: WorkspaceConfig,

    #[clap(flatten)]
    pub logging: LoggingConfig,

    /// The non-revocable key ID used for demo purposes
    #[clap(long, hide = true)]
    pub non_revocable_key_id: Option<Vec<String>>,

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
    pub fn load_configuration() -> KResult<Self> {
        Self::load_from_args(std::env::args())
    }

    /// Load configuration using a custom iterator of arguments (testable entry point).
    #[allow(clippy::print_stdout)] // Logging is not being initialized yet, just use standard prints
    pub fn load_from_args<I, T>(args: I) -> KResult<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // Collect args so we can re-use for parse + messages
        let args_vec: Vec<T> = args.into_iter().collect();
        // Parse preliminarily to capture the optional config path (this also handles --help / --version)
        let preliminary = Self::parse_from(args_vec);

        // Determine configuration file path precedence:
        // 1. Command line -c/--config
        // 2. COSMIAN_KMS_CONF environment variable (if exists and path exists)
        // 3. Default system path (if exists)
        // 4. Fall back to command line arguments & env vars (no file)

        let explicit = preliminary.config_path.clone();
        let env_path = std::env::var("COSMIAN_KMS_CONF").ok().map(PathBuf::from);
        let default_path = PathBuf::from(get_default_config_path());

        // Helper to load a TOML file into ClapConfig
        let load_file = |p: &PathBuf| -> KResult<Self> {
            let conf_content = std::fs::read_to_string(p).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot read KMS server config at: {} - {e:?}",
                    p.display()
                ))
            })?;
            toml::from_str(&conf_content).map_err(|e| {
                KmsError::ServerError(format!(
                    "Cannot parse kms server config at: {} - {e:?}",
                    p.display()
                ))
            })
        };

        if let Some(path) = explicit {
            if path.exists() {
                println!(
                    "Configuration file {} found (via -c/--config). Command line arguments and \
                     env variables are ignored.",
                    path.display()
                );
                return load_file(&path);
            }
            return Err(KmsError::ServerError(format!(
                "Configuration file specified with -c/--config not found: {}",
                path.display()
            )));
        }

        if let Some(env_path) = env_path {
            if env_path.exists() {
                println!(
                    "Configuration file {} found (via COSMIAN_KMS_CONF). Command line arguments \
                     and env variables are ignored.",
                    env_path.display()
                );
                return load_file(&env_path);
            }
            println!(
                "WARNING: Configuration file {} (COSMIAN_KMS_CONF) not found. Falling back.",
                env_path.display()
            );
        }

        if default_path.exists() {
            println!(
                "Configuration file {} found (default path). Command line arguments and \
                 environment variables are ignored.",
                default_path.display()
            );
            return load_file(&default_path);
        }

        println!(
            "No configuration file found (-c/--config, COSMIAN_KMS_CONF, default path). Using \
             command line arguments and environment variables."
        );
        Ok(preliminary)
    }
}

impl fmt::Debug for ClapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("");
        let x = x.field("config_path", &self.config_path);
        let x = x.field("db", &self.db);
        let x = if self.idp_auth.jwt_auth_provider.is_some() {
            x.field("idp_auth", &self.idp_auth)
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
        let x = x.field(
            "ui_index_html_folder",
            &self.ui_config.get_ui_index_html_folder(),
        );
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
        let x = x.field("HSM admin username", &self.hsm.hsm_admin);
        let x = x.field(
            "hsm_model",
            if self.hsm.hsm_slot.is_empty() {
                &"NO HSM"
            } else {
                &self.hsm.hsm_model
            },
        );
        let x = x.field("hsm_slots", &self.hsm.hsm_slot);
        let x = x.field(
            "hsm_passwords",
            &self
                .hsm
                .hsm_password
                .iter()
                .map(|_| "********")
                .collect::<Vec<&str>>(),
        );
        let x = x.field("key wrapping key", &self.key_encryption_key);
        let x = x.field("default unwrap type", &self.default_unwrap_type);
        let x = x.field("non_revocable_key_id", &self.non_revocable_key_id);
        let x = x.field("privileged_users", &self.privileged_users);

        x.finish()
    }
}

#[cfg(test)]
#[allow(unsafe_code, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Configuration precedence tests
    //!
    //! These tests validate the configuration loading precedence:
    //! 1. Command line -c/--config (highest precedence)
    //! 2. `COSMIAN_KMS_CONF` environment variable
    //! 3. Default system path
    //! 4. Command line arguments and environment variables (lowest precedence)
    //!
    //! IMPORTANT: These tests MUST be run serially to avoid environment variable
    //! and temporary file conflicts between parallel test runs:
    //! `RUST_TEST_THREADS=1 cargo test --lib config::command_line::clap_config::tests`

    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    use cosmian_logger::debug;

    use super::ClapConfig;

    // Global mutex to serialize environment variable access across all tests
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn write_temp(contents: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let thread_id = std::thread::current().id();
        let fname = format!("kms_test_conf_{ts}_{thread_id:?}.toml");
        p.push(fname);
        fs::write(&p, contents).expect("write temp toml");
        p
    }

    fn cleanup_temp(path: &PathBuf) {
        drop(std::fs::remove_file(path));
    }

    fn with_clean_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Acquire mutex to serialize environment variable access
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save current env state
        let original_env = std::env::var("COSMIAN_KMS_CONF").ok();

        // Clear env
        unsafe {
            std::env::remove_var("COSMIAN_KMS_CONF");
        }

        // Run test
        let result = f();

        // Restore original env state
        match original_env {
            Some(val) => unsafe { std::env::set_var("COSMIAN_KMS_CONF", val) },
            None => unsafe { std::env::remove_var("COSMIAN_KMS_CONF") },
        }

        result
        // Mutex is automatically released when _guard goes out of scope
    }

    fn set_var(key: &str, value: &Path) {
        unsafe {
            std::env::set_var(key, value.display().to_string());
        }
    }

    fn default_path_exists() -> bool {
        std::path::Path::new(&super::get_default_config_path()).exists()
    }

    #[test]
    fn precedence_cli_config_over_env_and_default() {
        with_clean_env(|| {
            let cli_file = write_temp("[http]\nport=12345\n");
            let env_file = write_temp("[http]\nport=54321\n");
            set_var("COSMIAN_KMS_CONF", &env_file);
            // Command line args like --port are completely ignored when -c config file is used
            let args = vec!["kms", "-c", cli_file.to_str().unwrap(), "--port", "9999"];
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(
                cfg.http.port, 12345,
                "-c config file takes precedence and ignores all other args"
            );
            cleanup_temp(&cli_file);
            cleanup_temp(&env_file);
        });
    }

    #[test]
    fn precedence_env_config_over_default() {
        with_clean_env(|| {
            // Create a unique temp file to simulate the COSMIAN_KMS_CONF file
            let env_file = write_temp("[http]\nport=23456\n");
            set_var("COSMIAN_KMS_CONF", &env_file);

            // Command line args are completely ignored when env config file exists
            let args = vec!["kms", "--port", "1111"];
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(
                cfg.http.port, 23456,
                "env config file ignores all command line args"
            );

            cleanup_temp(&env_file);
        });
    }

    #[test]
    fn precedence_default_config_over_args() {
        with_clean_env(|| {
            if default_path_exists() {
                eprintln!(
                    "Skipping precedence_default_config_over_args: default config already exists"
                );
            } else {
                // Create a temporary default config file for this test
                let default_content = "[http]\nport=34567\n";
                let default_path = PathBuf::from(super::get_default_config_path());
                if let Some(parent) = default_path.parent() {
                    drop(std::fs::create_dir_all(parent));
                }
                if std::fs::write(&default_path, default_content).is_ok() {
                    let args = vec!["kms", "--port", "2222"];
                    let cfg = ClapConfig::load_from_args(args).expect("load from args");
                    assert_eq!(
                        cfg.http.port, 34567,
                        "default config file ignores command line args"
                    );
                    drop(std::fs::remove_file(&default_path)); // cleanup
                } else {
                    eprintln!(
                        "Skipping precedence_default_config_over_args: cannot write to default \
                         path"
                    );
                }
            }
        });
    }

    #[test]
    fn env_config_nonexistent_falls_back_to_args() {
        with_clean_env(|| {
            set_var(
                "COSMIAN_KMS_CONF",
                &PathBuf::from("/nonexistent/config.toml"),
            );
            if default_path_exists() {
                eprintln!(
                    "Skipping env_config_nonexistent_falls_back_to_args: default config exists"
                );
                return;
            }
            let args = vec!["kms", "--port", "5555"];
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(
                cfg.http.port, 5555,
                "nonexistent env config should fall back to args"
            );
        });
    }

    #[test]
    fn uses_args_when_no_files() {
        with_clean_env(|| {
            if default_path_exists() {
                // Avoid false negative if a real default file is present on dev box
                eprintln!("Skipping uses_args_when_no_files: default config path exists");
                return;
            }
            let args = vec!["kms", "--port", "7777"]; // should be honored
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(cfg.http.port, 7777);
        });
    }

    #[test]
    fn error_when_cli_file_missing() {
        with_clean_env(|| {
            let args = vec!["kms", "-c", "/non/existent/xxxx__nope.toml"];
            let res = ClapConfig::load_from_args(args);
            assert!(res.is_err(), "should error for missing -c file");
            let err_msg = res.unwrap_err().to_string();
            assert!(err_msg.contains("Configuration file specified with -c/--config not found"));
        });
    }

    #[test]
    fn error_when_cli_file_invalid_toml() {
        with_clean_env(|| {
            let invalid_file = write_temp("invalid toml content [[[");
            let args = vec!["kms", "-c", invalid_file.to_str().unwrap()];
            let res = ClapConfig::load_from_args(args);
            assert!(res.is_err(), "should error for invalid toml file");
            let err_msg = res.unwrap_err().to_string();
            assert!(err_msg.contains("Cannot parse kms server config"));
            cleanup_temp(&invalid_file);
        });
    }

    #[test]
    fn complete_precedence_chain() {
        with_clean_env(|| {
            // Test the complete precedence: -c > COSMIAN_KMS_CONF > default > args
            let cli_file = write_temp("[http]\nport=11111\n");
            let env_file = write_temp("[http]\nport=22222\n");

            // 1. CLI config wins over everything
            set_var("COSMIAN_KMS_CONF", &env_file);
            let args = vec!["kms", "-c", cli_file.to_str().unwrap(), "--port", "9999"];
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(cfg.http.port, 11111, "CLI config should win");

            // 2. Test env config in a separate isolated scope
            cleanup_temp(&cli_file);

            let args = vec!["kms", "--port", "8888"];
            let cfg = ClapConfig::load_from_args(args).expect("load from args");
            assert_eq!(
                cfg.http.port, 22222,
                "Env config should win when no CLI config"
            );

            cleanup_temp(&env_file);

            // 3. Clear env var and test args win when no config files
            unsafe {
                std::env::remove_var("COSMIAN_KMS_CONF");
            }
            if !default_path_exists() {
                let args = vec!["kms", "--port", "7777"];
                let cfg = ClapConfig::load_from_args(args).expect("load from args");
                assert_eq!(cfg.http.port, 7777, "Args should win when no config files");
            }
        });
    }

    #[test]
    #[expect(clippy::unwrap_used)]
    fn test_server_configuration_file() {
        let conf = ClapConfig::default();
        let conf_str = toml::to_string_pretty(&conf).unwrap();
        debug!("Configuration TOML: {conf_str}");
    }

    #[test]
    #[expect(clippy::unwrap_used)]
    fn test_server_idp() {
        let mut conf = ClapConfig::default();
        conf.idp_auth.jwt_auth_provider = Some(vec![
            "https://issuer1.example.com,jwks_uri_1,audience1,audience2".to_owned(),
            "https://issuer2.example.com,,audience3".to_owned(),
            "https://issuer3.example.com".to_owned(),
        ]);
        let conf_str = toml::to_string_pretty(&conf).unwrap();
        debug!("Configuration TOML: {conf_str}");
    }
}
