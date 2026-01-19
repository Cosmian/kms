use std::sync::Arc;

use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    result::KResult,
    start_kms_server::start_kms_server,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::KmipResultHelper;
#[cfg(feature = "timeout")]
use cosmian_logger::warn;
use cosmian_logger::{TelemetryConfig, TracingConfig, info, tracing_init};
use dotenvy::dotenv;
use openssl::provider::Provider;
use tracing::span;

#[cfg(feature = "timeout")]
mod expiry;

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
/// then parses the command line arguments using [`ClapConfig::parse()`](https://docs.rs/clap/latest/clap/struct.ClapConfig.html#method.parse).
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> KResult<()> {
    // Load variable from a .env file
    dotenv().ok();

    let clap_config = ClapConfig::load_configuration()?;

    let info_only = clap_config.info;

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
        log_to_file: clap_config.logging.rolling_log_dir.clone().map(|dir| {
            (
                dir,
                clap_config
                    .logging
                    .rolling_log_name
                    .clone()
                    .unwrap_or_else(|| "kms".to_owned()),
            )
        }),
        with_ansi_colors: clap_config.logging.ansi_colors,
    });

    // TODO: For an unknown reason, this span never goes to OTLP
    let span = span!(tracing::Level::TRACE, "kms");
    let _guard = span.enter();

    #[cfg(not(feature = "non-fips"))]
    info!(
        "OpenSSL FIPS mode version: {}, in {}, number: {:x}",
        openssl::version::version(),
        openssl::version::dir(),
        openssl::version::number()
    );

    #[cfg(feature = "non-fips")]
    info!(
        "OpenSSL default mode, version: {}, in {}, number: {:x}",
        openssl::version::version(),
        openssl::version::dir(),
        openssl::version::number()
    );

    // For an explanation of OpenSSL providers,
    //  https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // In FIPS mode, we only load the FIPS provider
    #[cfg(not(feature = "non-fips"))]
    Provider::load(None, "fips")?;

    // Not in FIPS mode and version > 3.0: load the default provider and the legacy provider
    // so that we can use the legacy algorithms.
    // particularly those used for old PKCS#12 formats
    #[cfg(feature = "non-fips")]
    if openssl::version::number() >= 0x3000_0000 {
        Provider::try_load(None, "legacy", true)
            .context("unable to load the openssl legacy provider")?;
    } else {
        // In version < 3.0, we only load the default provider
        Provider::load(None, "default")?;
    }

    // Instantiate a config object using the env variables and the args of the binary
    info!("Command line / file config: {clap_config:#?}");

    // Parse the Server Config from the command line arguments
    let server_params = Arc::new(ServerParams::try_from(clap_config)?);

    if info_only {
        info!("Server started with --info. Exiting");
        return Ok(());
    }

    #[cfg(feature = "timeout")]
    info!("Feature Timeout enabled");
    #[cfg(test)]
    info!("Feature Test enabled");

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server(server_params, None)), demo).await
    };

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    Box::pin(start_kms_server(server_params, None)).await?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
mod tests {
    use std::path::PathBuf;

    use cosmian_kms_server::config::{
        ClapConfig, GoogleCseConfig, HttpConfig, IdpAuthConfig, LoggingConfig, MainDBConfig,
        OidcConfig, ProxyConfig, SocketServerConfig, TlsConfig, UiConfig, WorkspaceConfig,
    };

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
            },
            http: HttpConfig {
                port: 443,
                hostname: "[hostname]".to_owned(),
                api_token_id: None,
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
            ui_config: UiConfig {
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
            kms_public_url: Some("[kms_public_url]".to_owned()),
            workspace: WorkspaceConfig {
                root_data_path: PathBuf::from("[root data path]"),
                tmp_path: PathBuf::from("[tmp path]"),
            },
            default_username: "[default username]".to_owned(),
            force_default_username: false,
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
            },
            info: false,
            hsm: cosmian_kms_server::config::HsmConfig {
                hsm_model: String::new(),
                hsm_admin: String::new(),
                hsm_slot: vec![],
                hsm_password: vec![],
            },
            key_encryption_key: Some("key wrapping key".to_owned()),
            default_unwrap_type: None,
            non_revocable_key_id: None,
            privileged_users: None,
        };

        let toml_string = r#"
default_username = "[default username]"
force_default_username = false
ms_dke_service_url = "[ms dke service url]"
info = false
hsm_model = ""
hsm_admin = ""
hsm_slot = []
hsm_password = []
key_encryption_key = "key wrapping key"
kms_public_url = "[kms_public_url]"

[db]
database_type = "[redis-findex, postgresql,...]"
database_url = "[redis urls]"
sqlite_path = "[sqlite path]"
redis_master_password = "[redis master password]"
clear_database = false
unwrapped_cache_max_age = 15

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

[proxy]
proxy_url = "https://proxy.example.com:8080"
proxy_basic_auth_username = "[proxy username]"
proxy_basic_auth_password = "[proxy password]"
proxy_exclusion_list = ["domain1", "domain2"]

[idp_auth]
jwt_auth_provider = ["jwt issuer uri 1,jwks uri 1,jwt audience 1", "jwt issuer uri 2,jwks uri 2,jwt audience 2"]

[ui_config]
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

[workspace]
root_data_path = "[root data path]"
tmp_path = "[tmp path]"

[logging]
rust_log = "info,cosmian_kms=debug"
otlp = "http://localhost:4317"
quiet = false
log_to_syslog = false
rolling_log_dir = "[rolling log dir]"
rolling_log_name = "kms_log"
enable_metering = false
environment = "development"
ansi_colors = false
"#;

        assert_eq!(toml_string.trim(), toml::to_string(&config).unwrap().trim());
    }
}
