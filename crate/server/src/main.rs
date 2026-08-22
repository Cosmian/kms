use std::sync::Arc;

use cosmian_kms_server::{
    config::{ClapConfig, OpenTelemetryConfig, ServerParams, wizard::run_configure_wizard},
    core::KMS,
    openssl_providers::{cpu_features_info, safe_openssl_version_info},
    result::{KResult, KResultHelper},
};
use cosmian_logger::{TelemetryConfig, TracingConfig, info, tracing_init};
use dotenvy::dotenv;
use tracing::span;

/// Get the default `RUST_LOG` configuration if not set
fn get_default_rust_log() -> String {
    "info,cosmian=info,cosmian_kms_server=info,actix_web=info".to_owned()
}

/// Get the appropriate `rust_log` value, preferring config over environment
fn get_effective_rust_log(config_rust_log: Option<String>, info_only: bool) -> Option<String> {
    if info_only {
        Some("info".to_owned())
    } else {
        config_rust_log.or_else(|| {
            // Only fall back to environment or default if not in config
            std::env::var("RUST_LOG")
                .ok()
                .or_else(|| Some(get_default_rust_log()))
        })
    }
}

/// The main entry point of the program.
///
/// This function sets up the necessary environment variables and logging options,
/// then parses the command line arguments using `ClapConfig::parse()`.
///
/// On Windows, if the process was launched by the Service Control Manager, it
/// dispatches to the Windows service entry point instead.
///
/// The tokio runtime is sized to the available parallelism reported by the OS.
fn main() {
    // On Windows, attempt to register with the SCM.  If the process was launched
    // by the SCM, `try_run_as_service()` blocks until the service stops and then
    // returns Ok(()).  If launched from a console, it returns Err (not an SCM
    // launch) and we fall through to the normal interactive startup path.
    #[cfg(windows)]
    {
        match cosmian_kms_server::windows_service::try_run_as_service() {
            Ok(()) => {
                // Service ran and stopped — exit cleanly.
                return;
            }
            Err(_e) => {
                // Not launched by the SCM — continue with normal console startup.
            }
        }
    }

    let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(parallelism)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        if let Err(e) = run().await {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    });
}

async fn run() -> KResult<()> {
    // Load variable from a .env file
    dotenv().ok();

    // Early dispatch: if the first argument is "configure", run the interactive wizard
    if std::env::args().nth(1).as_deref() == Some("configure") {
        return run_configure_wizard();
    }

    let clap_config = ClapConfig::load_configuration()?;

    if clap_config.print_default_config {
        let commented = ClapConfig::default_config_with_comments()?;
        #[allow(clippy::print_stdout)]
        {
            println!("{commented}");
        }
        return Ok(());
    }

    let info_only = clap_config.info;

    // Reject plaintext OTLP endpoints unless explicitly allowed
    if let Some(url) = &clap_config.logging.otlp {
        let otel_config = Some(OpenTelemetryConfig {
            otlp_url: Some(url.clone()),
            otlp_allow_insecure: clap_config.logging.otlp_allow_insecure,
            enable_metering: clap_config.logging.enable_metering,
            environment: clap_config.logging.environment.clone(),
        });
        KMS::validate_otlp_url(url, &otel_config)?;
    }

    // ── Pre-validate rolling log directory ──────────────────────────────────
    // tracing-appender panics if the directory is not writable.  Gracefully
    // disable file logging when the configured path cannot be used.
    let log_to_file = clap_config.logging.rolling_log_dir.clone().and_then(|dir| {
        // Attempt to create the directory hierarchy.
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "WARNING: Cannot create rolling log directory '{}': {e}. \
                     File logging disabled. Use --rolling-log-dir or KMS_ROLLING_LOG_DIR \
                     to specify an alternative writable path.",
                dir.display()
            );
            return None;
        }
        // Verify write access by creating and removing a temporary probe file.
        let probe = dir.join(".cosmian_kms_write_probe");
        match std::fs::File::create(&probe) {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(&probe).ok();
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Rolling log directory '{}' is not writable: {e}. \
                         File logging disabled. Use --rolling-log-dir or KMS_ROLLING_LOG_DIR \
                         to specify an alternative writable path.",
                    dir.display()
                );
                return None;
            }
        }
        let name = clap_config
            .logging
            .rolling_log_name
            .clone()
            .unwrap_or_else(|| "kms".to_owned());
        Some((dir, name))
    });

    // Initialize the tracing system
    let _otel_guard = tracing_init(&TracingConfig {
        service_name: "cosmian_kms".to_owned(),
        otlp: clap_config
            .logging
            .otlp
            .as_ref()
            .map(|url| TelemetryConfig {
                version: option_env!("CARGO_PKG_VERSION").map(String::from),
                environment: clap_config.logging.environment.clone(),
                otlp_url: url.to_owned(),
                enable_metering: clap_config.logging.enable_metering,
            }),
        no_log_to_stdout: clap_config.logging.quiet,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: clap_config.logging.log_to_syslog,
        // Use safe rust_log configuration without environment variable setting
        rust_log: get_effective_rust_log(clap_config.logging.rust_log.clone(), info_only),
        log_to_file,
        with_ansi_colors: clap_config.logging.ansi_colors,
    });

    // TODO: For an unknown reason, this span never goes to OTLP
    let span = span!(tracing::Level::TRACE, "kms");
    let _guard = span.enter();

    let (ossl_version, ossl_dir, ossl_number) = safe_openssl_version_info();
    if ossl_number == 0 {
        tracing::error!(
            "OpenSSL does not appear to be available (version number is 0). \
             Please verify that OpenSSL is correctly installed and accessible."
        );
        return Err(cosmian_kms_server::error::KmsError::ServerError(
            "OpenSSL is not available – cannot start the KMS server".to_owned(),
        ));
    }
    info!(
        "Starting Cosmian KMS server version {}",
        env!("CARGO_PKG_VERSION")
    );
    info!("OpenSSL version: {ossl_version}, in {ossl_dir}, number: {ossl_number:x}");
    info!("{}", cpu_features_info());

    // For an explanation of OpenSSL providers,
    //  https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // Load the appropriate OpenSSL provider based on FIPS mode and OpenSSL version
    cosmian_kms_server::openssl_providers::init_openssl_providers()
        .context("unable to load the required OpenSSL provider")?;

    // Instantiate a config object using the env variables and the args of the binary
    info!("Command line / file config: {clap_config:#?}");

    // --info is a lightweight probe: log the configuration then exit without
    // initialising the database, workspace directories etc.
    if info_only {
        info!("Server started with --info. Exiting");
        return Ok(());
    }

    // Parse the Server Config from the command line arguments
    let server_params = Arc::new(ServerParams::try_from(clap_config)?);

    #[cfg(test)]
    info!("Feature Test enabled");

    // Start the KMS
    Box::pin(cosmian_kms_server::start_kms_server::start_kms_server(
        server_params,
        None,
    ))
    .await?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
mod tests {
    use std::path::PathBuf;

    use cosmian_kms_server::{
        config::{
            AuthVerifierConfig, AzureEkmConfig, ClapConfig, GoogleCseConfig, HttpConfig,
            IdpAuthConfig, JwksEndpointConfig, KmipPolicyConfig, LoggingConfig, MainDBConfig,
            OidcConfig, ProxyConfig, RolesConfig, SocketServerConfig, TlsConfig, UiConfig,
            WorkspaceConfig,
        },
        routes::aws_xks::AwsXksConfig,
    };
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::extra::tagging::VENDOR_ID_COSMIAN;

    #[cfg(feature = "non-fips")]
    #[test]
    fn test_toml() {
        let config = ClapConfig {
            config_path: None,
            db: MainDBConfig {
                database_type: Some("[redis-findex, postgresql,...]".to_owned()),
                database_url: Some("[redis urls]".to_owned()),
                sqlite_path: PathBuf::from("[sqlite path]"),
                max_connections: None,
                #[cfg(feature = "non-fips")]
                redis_master_password: Some("[redis master password]".to_owned()),
                #[cfg(feature = "non-fips")]
                clear_database: false,
                unwrapped_cache_max_age: 15,
                unwrapped_cache_max_size: 1000,
                unwrapped_cache_max_ttl: None,
                disable_unwrapped_cache: false,
            },
            socket_server: SocketServerConfig {
                socket_server_start: false,
                socket_server_port: 5696,
                socket_server_hostname: "0.0.0.0".to_owned(),
            },
            tls: TlsConfig {
                tls_p12_file: Some(PathBuf::from("[tls p12 file]")),
                tls_p12_password: Some("[tls p12 password]".to_owned()),
                clients_ca_cert_file: Some(PathBuf::from("[authority cert file]")),
                tls_cipher_suites: Some("TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256".to_owned()),
                ..Default::default()
            },
            http: HttpConfig {
                port: 443,
                hostname: "[hostname]".to_owned(),
                api_token_id: None,
                rate_limit_per_second: Some(100),
                cors_allowed_origins: None,
                http_workers: None,
                jwks_enabled: false,
            },
            proxy: ProxyConfig {
                proxy_url: Some("https://proxy.example.com:8080".to_owned()),
                proxy_basic_auth_username: Some("[proxy username]".to_owned()),
                proxy_basic_auth_password: Some("[proxy password]".to_owned()),
                proxy_custom_auth_header: None,
                proxy_exclusion_list: Some(vec!["domain1".to_owned(), "domain2".to_owned()]),
            },
            idp_auth: IdpAuthConfig {
                jwt_auth_provider: Some(vec![
                    "jwt issuer uri 1,jwks uri 1,jwt audience 1".to_owned(),
                    "jwt issuer uri 2,jwks uri 2,jwt audience 2".to_owned(),
                ]),
            },
            auth_verifier: AuthVerifierConfig::default(),
            ui_config: UiConfig {
                enable: true,
                ui_index_html_folder: Some("[ui index html folder]".to_owned()),
                ui_session_salt: None,
                ui_oidc_auth: OidcConfig {
                    ui_oidc_client_id: Some("[client id]".to_owned()),
                    ui_oidc_client_secret: Some("[client secret]".to_owned()),
                    ui_oidc_issuer_url: Some("[issuer url]".to_owned()),
                    ui_oidc_logout_url: Some("[logout url]".to_owned()),
                },
            },
            google_cse_config: GoogleCseConfig {
                google_cse_enable: false,
                google_cse_disable_tokens_validation: false,
                google_cse_incoming_url_whitelist: Some(vec![
                    "[kacls_url_1]".to_owned(),
                    "[kacls_url_2]".to_owned(),
                ]),
                google_cse_migration_key: None,
            },
            azure_ekm_config: AzureEkmConfig {
                azure_ekm_enable: false,
                azure_ekm_path_prefix: None,
                azure_ekm_disable_client_auth: false,
                azure_ekm_proxy_vendor: String::new(),
                azure_ekm_proxy_name: String::new(),
                azure_ekm_ekm_vendor: String::new(),
                azure_ekm_ekm_product: String::new(),
            },
            jwks_endpoint: JwksEndpointConfig::default(),
            kms_public_url: Some("[kms_public_url]".to_owned()),
            workspace: WorkspaceConfig {
                root_data_path: PathBuf::from("[root data path]"),
                tmp_path: PathBuf::from("[tmp path]"),
            },
            default_username: "[default username]".to_owned(),
            force_default_username: false,
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            kmip_policy: KmipPolicyConfig::default(),
            ms_dke_service_url: Some("[ms dke service url]".to_owned()),
            logging: LoggingConfig {
                rust_log: Some("info,cosmian_kms=debug".to_owned()),
                otlp: Some("http://localhost:4317".to_owned()),
                quiet: false,
                #[cfg(not(target_os = "windows"))]
                log_to_syslog: false,
                rolling_log_dir: Some(PathBuf::from("[rolling log dir]")),
                rolling_log_name: Some("kms_log".to_owned()),
                enable_metering: false,
                environment: Some("development".to_owned()),
                ansi_colors: false,
                otlp_allow_insecure: false,
            },
            info: false,
            hsm: cosmian_kms_server::config::HsmConfig {
                hsm_model: String::new(),
                hsm_admin: vec![],
                hsm_slot: vec![],
                hsm_password: vec![],
            },
            hsm_instances: vec![],
            aws_xks_config: AwsXksConfig {
                aws_xks_enable: true,
                aws_xks_region: Some("us-east-1".to_owned()),
                aws_xks_service: Some("kms-xks-proxy".to_owned()),
                aws_xks_sigv4_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_owned()),
                aws_xks_sigv4_secret_access_key: Some(
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
                ),
            },
            key_encryption_key: Some("key wrapping key".to_owned()),
            default_unwrap_type: None,
            non_revocable_key_id: None,
            privileged_users: None,
            roles: RolesConfig::default(),
            print_default_config: false,
            secret_backends: cosmian_kms_server::config::SecretBackendConfig::default(),
            auto_rotation_check_interval_secs: 0,
            keyset_warn_depth: 5,
            vault: cosmian_kms_server::config::VaultConfig::default(),
        };

        let toml_string = r#"
vendor_identification = "cosmian"
default_username = "[default username]"
force_default_username = false
ms_dke_service_url = "[ms dke service url]"
info = false
hsm_model = ""
hsm_admin = []
hsm_slot = []
hsm_password = []
hsm_instances = []
key_encryption_key = "key wrapping key"
kms_public_url = "[kms_public_url]"
auto_rotation_check_interval_secs = 0
keyset_warn_depth = 5

[db]
database_type = "[redis-findex, postgresql,...]"
database_url = "[redis urls]"
sqlite_path = "[sqlite path]"
redis_master_password = "[redis master password]"
clear_database = false
unwrapped_cache_max_age = 15
unwrapped_cache_max_size = 1000
disable_unwrapped_cache = false

[socket_server]
socket_server_start = false
socket_server_port = 5696
socket_server_hostname = "0.0.0.0"

[tls]
tls_p12_file = "[tls p12 file]"
tls_p12_password = "[tls p12 password]"
clients_ca_cert_file = "[authority cert file]"
tls_cipher_suites = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256"

[http]
port = 443
hostname = "[hostname]"
rate_limit_per_second = 100

[proxy]
proxy_url = "https://proxy.example.com:8080"
proxy_basic_auth_username = "[proxy username]"
proxy_basic_auth_password = "[proxy password]"
proxy_exclusion_list = ["domain1", "domain2"]

[idp_auth]
jwt_auth_provider = ["jwt issuer uri 1,jwks uri 1,jwt audience 1", "jwt issuer uri 2,jwks uri 2,jwt audience 2"]

[auth_verifier]
auth_verifier_accept_invalid_certs = false

[ui_config]
enable = true
ui_index_html_folder = "[ui index html folder]"

[ui_config.ui_oidc_auth]
ui_oidc_client_id = "[client id]"
ui_oidc_client_secret = "[client secret]"
ui_oidc_issuer_url = "[issuer url]"
ui_oidc_logout_url = "[logout url]"

[google_cse_config]
google_cse_enable = false
google_cse_disable_tokens_validation = false
google_cse_incoming_url_whitelist = ["[kacls_url_1]", "[kacls_url_2]"]

[azure_ekm_config]
azure_ekm_enable = false

[workspace]
root_data_path = "[root data path]"
tmp_path = "[tmp path]"

[logging]
rust_log = "info,cosmian_kms=debug"
otlp = "http://localhost:4317"
otlp_allow_insecure = false
quiet = false
log_to_syslog = false
rolling_log_dir = "[rolling log dir]"
rolling_log_name = "kms_log"
enable_metering = false
environment = "development"
ansi_colors = false

[roles]
crypto_officer_require_ceremony = false

[aws_xks_config]
aws_xks_enable = true
aws_xks_region = "us-east-1"
aws_xks_service = "kms-xks-proxy"
aws_xks_sigv4_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_xks_sigv4_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

[kmip.allowlists]

[jwks_endpoint]
jwks_endpoint_enabled = false
jwks_endpoint_max_keys = 50
jwks_endpoint_auto_tag = true

[vault]
vault_api_enabled = false
vault_auth_verifier_accept_invalid_certs = false
vault_transit_mount = ""
vault_pki_mount = ""
vault_pki_ca_key_label = ""
vault_token_cache_ttl_secs = 0
"#;

        assert_eq!(toml_string.trim(), toml::to_string(&config).unwrap().trim());
    }
}
