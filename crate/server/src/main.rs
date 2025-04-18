#[cfg(not(feature = "fips"))]
use cosmian_kmip::KmipResultHelper;
use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    result::KResult,
    start_kms_server::start_kms_server,
    telemetry::initialize_telemetry,
};
use dotenvy::dotenv;
use openssl::provider::Provider;
#[cfg(feature = "timeout")]
use tracing::warn;
use tracing::{debug, info, span};

#[cfg(feature = "timeout")]
mod expiry;

/// The main entrypoint of the program.
///
/// This function sets up the necessary environment variables and logging options,
/// then parses the command line arguments using [`ClapConfig::parse()`](https://docs.rs/clap/latest/clap/struct.ClapConfig.html#method.parse).
#[tokio::main]
async fn main() -> KResult<()> {
    // Set up environment variables and logging options
    if std::env::var("RUST_BACKTRACE").is_err() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "full");
        }
    }
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var(
                "RUST_LOG",
                "info,cosmian=info,cosmian_kms_server=info,actix_web=info,sqlx::query=error,\
                 mysql=info",
            );
        }
    }

    // Load variable from a .env file
    dotenv().ok();

    let clap_config = ClapConfig::load_from_file()?;

    let info_only = clap_config.info;
    if info_only {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    // Start the telemetry
    initialize_telemetry(&clap_config.telemetry)?;

    //TODO: For an unknown reason, this span never goes to OTLP
    let span = span!(tracing::Level::INFO, "start");
    let _guard = span.enter();

    // print openssl version
    #[cfg(feature = "fips")]
    info!(
        "OpenSSL FIPS mode version: {}, in {}, number: {:x}",
        openssl::version::version(),
        openssl::version::dir(),
        openssl::version::number()
    );

    #[cfg(not(feature = "fips"))]
    info!(
        "OpenSSL default mode, version: {}, in {}, number: {:x}",
        openssl::version::version(),
        openssl::version::dir(),
        openssl::version::number()
    );

    // For an explanation of openssl providers, see
    // see https://docs.openssl.org/3.1/man7/crypto/#openssl-providers

    // In FIPS mode, we only load the fips provider
    #[cfg(feature = "fips")]
    Provider::load(None, "fips")?;

    // Not in FIPS mode and version > 3.0: load the default provider and the legacy provider
    // so that we can use the legacy algorithms
    // particularly those used for old PKCS#12 formats
    #[cfg(not(feature = "fips"))]
    if openssl::version::number() >= 0x30000000 {
        Provider::try_load(None, "legacy", true)
            .context("export: unable to load the openssl legacy provider")?;
    } else {
        // In version < 3.0, we only load the default provider
        Provider::load(None, "default")?;
    };

    // Instantiate a config object using the env variables and the args of the binary
    debug!("Command line config: {clap_config:#?}");

    // Parse the Server Config from the command line arguments
    let server_params = ServerParams::try_from(clap_config)?;

    if info_only {
        info!("Server started with --info. Exiting");
        return Ok(());
    }

    #[cfg(feature = "timeout")]
    info!("Feature Timeout enabled");
    #[cfg(feature = "insecure")]
    info!("Feature Insecure enabled");

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server(server_params, None)), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    Box::pin(start_kms_server(server_params, None)).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cosmian_kms_server::{
        config::{
            ClapConfig, HttpConfig, JwtAuthConfig, MainDBConfig, OidcConfig, UiConfig,
            WorkspaceConfig,
        },
        telemetry::TelemetryConfig,
    };

    #[test]
    fn test_toml() {
        let config = ClapConfig {
            db: MainDBConfig {
                database_type: Some("[redis-findex, postgresql,...]".to_owned()),
                database_url: Some("[redis urls]".to_owned()),
                sqlite_path: PathBuf::from("[sqlite path]"),
                redis_master_password: Some("[redis master password]".to_owned()),
                redis_findex_label: Some("[redis findex label]".to_owned()),
                clear_database: false,
            },
            http: HttpConfig {
                port: 443,
                hostname: "[hostname]".to_owned(),
                https_p12_file: Some(PathBuf::from("[https p12 file]")),
                https_p12_password: Some("[https p12 password]".to_owned()),
                authority_cert_file: Some(PathBuf::from("[authority cert file]")),
                api_token_id: None,
            },
            auth: JwtAuthConfig {
                jwt_issuer_uri: Some(vec![
                    "[jwt issuer uri 1]".to_owned(),
                    "[jwt issuer uri 2]".to_owned(),
                ]),
                jwks_uri: Some(vec!["[jwks uri 1]".to_owned(), "[jwks uri 2]".to_owned()]),
                jwt_audience: Some(vec![
                    "[jwt audience 1]".to_owned(),
                    "[jwt audience 2]".to_owned(),
                ]),
            },
            ui_config: UiConfig {
                ui_index_html_folder: "[ui index html folder]".to_owned(),
                ui_oidc_auth: OidcConfig {
                    ui_oidc_client_id: Some("[client id]".to_owned()),
                    ui_oidc_client_secret: Some("[client secret]".to_owned()),
                    ui_oidc_issuer_url: Some("[issuer url]".to_owned()),
                    ui_oidc_logout_url: Some("[logout url]".to_owned()),
                },
            },
            kms_public_url: Some("[kms_public_url]".to_owned()),
            workspace: WorkspaceConfig {
                root_data_path: PathBuf::from("[root data path]"),
                tmp_path: PathBuf::from("[tmp path]"),
            },
            default_username: "[default username]".to_owned(),
            force_default_username: false,
            google_cse_disable_tokens_validation: false,
            google_cse_kacls_url: Some("[google cse kacls url]".to_owned()),
            ms_dke_service_url: Some("[ms dke service url]".to_owned()),
            telemetry: TelemetryConfig {
                otlp: Some("http://localhost:4317".to_owned()),
                quiet: false,
            },
            info: false,
            hsm_model: "".to_string(),
            hsm_admin: "".to_string(),
            hsm_slot: vec![],
            hsm_password: vec![],
            non_revocable_key_id: None,
            privileged_users: None,
        };

        let toml_string = r#"
default_username = "[default username]"
force_default_username = false
google_cse_kacls_url = "[google cse kacls url]"
google_cse_disable_tokens_validation = false
ms_dke_service_url = "[ms dke service url]"
info = false
hsm_model = ""
hsm_admin = ""
hsm_slot = []
hsm_password = []
kms_public_url = "[kms_public_url]"

[db]
database_type = "[redis-findex, postgresql,...]"
database_url = "[redis urls]"
sqlite_path = "[sqlite path]"
redis_master_password = "[redis master password]"
redis_findex_label = "[redis findex label]"
clear_database = false

[http]
port = 443
hostname = "[hostname]"
https_p12_file = "[https p12 file]"
https_p12_password = "[https p12 password]"
authority_cert_file = "[authority cert file]"

[auth]
jwt_issuer_uri = ["[jwt issuer uri 1]", "[jwt issuer uri 2]"]
jwks_uri = ["[jwks uri 1]", "[jwks uri 2]"]
jwt_audience = ["[jwt audience 1]", "[jwt audience 2]"]

[ui_config]
ui_index_html_folder = "[ui index html folder]"

[ui_config.ui_oidc_auth]
ui_oidc_client_id = "[client id]"
ui_oidc_client_secret = "[client secret]"
ui_oidc_issuer_url = "[issuer url]"
ui_oidc_logout_url = "[logout url]"

[workspace]
root_data_path = "[root data path]"
tmp_path = "[tmp path]"

[telemetry]
otlp = "http://localhost:4317"
quiet = false
"#;

        // println!("{}", toml::to_string(&config).unwrap().trim());
        assert_eq!(toml_string.trim(), toml::to_string(&config).unwrap().trim());
    }
}
