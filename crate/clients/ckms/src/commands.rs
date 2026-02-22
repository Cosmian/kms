use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_cli::{
    actions::kms::actions::KmsActions,
    reexport::cosmian_kms_client::{
        GmailApiConf, KmsClient,
        reexport::cosmian_http_client::{HttpClientConfig, ProxyParams},
    },
};
use cosmian_logger::{info, log_init, trace};
use dialoguer::{Confirm, Input, Password, Select};
use url::Url;

use crate::{
    actions::markdown::MarkdownAction, cli_error, config::ClientConfig,
    error::result::CosmianResult, proxy_config::ProxyConfig,
};

/// Updates proxy configuration for the KMS client
///
/// # Arguments
/// * `config` - Mutable reference to the client configuration
/// * `proxy_config` - The proxy configuration from CLI arguments
///
/// # Errors
/// Returns an error if the proxy URL cannot be parsed
fn update_proxy_config(config: &mut ClientConfig, proxy_config: &ProxyConfig) -> CosmianResult<()> {
    let proxy_params: Option<ProxyParams> = if let Some(url) = &proxy_config.proxy_url {
        let exclusion_list = proxy_config
            .proxy_exclusion_list
            .clone()
            .unwrap_or_default();
        Some(ProxyParams {
            url: Url::parse(url).map_err(|e| cli_error!("Failed parsing the Proxy URL: {e}"))?,
            basic_auth_username: proxy_config.proxy_basic_auth_username.clone(),
            basic_auth_password: proxy_config.proxy_basic_auth_password.clone(),
            custom_auth_header: proxy_config.proxy_custom_auth_header.clone(),
            exclusion_list,
        })
    } else {
        None
    };

    if let Some(proxy_params) = proxy_params {
        config.kms_config.http_config.proxy_params = Some(proxy_params);
    }

    Ok(())
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Configuration file location
    ///
    /// This is an alternative to the env variable `CKMS_CONF_PATH`.
    /// Takes precedence over `CKMS_CONF_PATH` env variable.
    #[arg(short, env = "CKMS_CONF_PATH", long)]
    conf_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: CliCommands,

    /// The URL of the KMS
    #[arg(long, env = "KMS_DEFAULT_URL", action)]
    pub url: Option<String>,

    /// Output the KMS JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long)]
    pub print_json: bool,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS
    /// KMS server running an invalid or insecure SSL certificate
    #[arg(long)]
    pub accept_invalid_certs: bool,

    #[clap(flatten)]
    pub proxy: ProxyConfig,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CliCommands {
    /// Handle KMS actions
    #[command(subcommand)]
    Kms(KmsActions),
    /// Action to auto-generate doc in Markdown format
    /// Run `cargo run --bin ckms -- markdown
    /// documentation/docs/cli/main_commands.md`
    #[clap(hide = true)]
    Markdown(MarkdownAction),
    /// Configure the Cosmian CLI (creates/updates cosmian.toml)
    Configure,
}

/// Main function for the Cosmian CLI application.
///
/// This function initializes logging, parses command-line arguments, and
/// executes the appropriate command based on the provided arguments. It
/// supports various subcommands for interacting with the Cosmian CLI, such as login,
/// logout, locating objects, and more.
///
/// # Errors
///
/// This function will return an error if:
/// - The logging initialization fails.
/// - The command-line arguments cannot be parsed.
/// - The configuration file cannot be located or loaded.
/// - Any of the subcommands fail during their execution.
pub async fn cosmian_main() -> CosmianResult<()> {
    log_init(None);
    info!("Starting Cosmian CLI");
    let cli = Cli::parse();

    let mut config = ClientConfig::load(cli.conf_path.clone())?;

    // Handle KMS configuration
    if let Some(url) = cli.url.clone() {
        config.kms_config.http_config.server_url = url;
    }
    if cli.accept_invalid_certs {
        config.kms_config.http_config.accept_invalid_certs = true;
    }
    config.kms_config.print_json = Some(cli.print_json);

    update_proxy_config(&mut config, &cli.proxy)?;

    trace!("Configuration: {config:#?}");

    // Instantiate the KMS client
    let kms_rest_client = KmsClient::new_with_config(config.kms_config.clone())?;

    match &cli.command {
        CliCommands::Markdown(action) => {
            action.process(&Cli::command())?;
            return Ok(());
        }
        CliCommands::Configure => {
            run_configure_wizard(config.clone())?;
            return Ok(());
        }
        CliCommands::Kms(kms_actions) => {
            let new_kms_config = Box::pin(kms_actions.process(kms_rest_client)).await?;
            if config.kms_config != new_kms_config {
                config.kms_config = new_kms_config;
                config.save(cli.conf_path.clone())?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
fn configure_http(label: &str, http: &mut HttpClientConfig) -> CosmianResult<()> {
    println!("-- {label} HTTP settings --");

    let server_url: String = Input::new()
        .with_prompt("Server URL")
        .default(http.server_url.clone())
        .interact_text()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;
    http.server_url = server_url;

    let accept_invalid_certs: bool = Confirm::new()
        .with_prompt("Accept invalid TLS certificates?")
        .default(http.accept_invalid_certs)
        .interact()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;
    http.accept_invalid_certs = accept_invalid_certs;

    // Authentication method selection
    let current_auth_index = match (
        http.ssl_client_pkcs12_path.is_some(),
        http.access_token.is_some(),
    ) {
        (false, false) => 0,
        (false, true) => 1,
        (true, false) => 2,
        (true, true) => 3,
    };
    let auth_methods = vec![
        "None",
        "Bearer token",
        "Client certificate (PKCS#12)",
        "Both (cert + token)",
    ];
    let choice = Select::new()
        .with_prompt("Authentication method")
        .items(&auth_methods)
        .default(current_auth_index)
        .interact()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;

    // Reset auth fields
    http.access_token = None;
    http.ssl_client_pkcs12_path = None;
    http.ssl_client_pkcs12_password = None;

    match choice {
        0 => {}
        1 => {
            let token: String = Input::new()
                .with_prompt("Bearer token (leave empty to skip)")
                .allow_empty(true)
                .with_initial_text(http.access_token.clone().unwrap_or_default())
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            if !token.is_empty() {
                http.access_token = Some(token);
            }
        }
        2 => {
            let pkcs12_path: String = Input::new()
                .with_prompt("Client PKCS#12 path (.p12)")
                .allow_empty(true)
                .with_initial_text(http.ssl_client_pkcs12_path.clone().unwrap_or_default())
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            if !pkcs12_path.is_empty() {
                http.ssl_client_pkcs12_path = Some(pkcs12_path);
                let pw: String = Password::new()
                    .with_prompt("Client PKCS#12 password (leave empty if none)")
                    .allow_empty_password(true)
                    .interact()
                    .map_err(|e| cli_error!("Prompt failed: {e}"))?;
                if !pw.is_empty() {
                    http.ssl_client_pkcs12_password = Some(pw);
                }
            }
        }
        3 => {
            let token: String = Input::new()
                .with_prompt("Bearer token")
                .allow_empty(false)
                .with_initial_text(http.access_token.clone().unwrap_or_default())
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            http.access_token = Some(token);

            let pkcs12_path: String = Input::new()
                .with_prompt("Client PKCS#12 path (.p12)")
                .allow_empty(false)
                .with_initial_text(http.ssl_client_pkcs12_path.clone().unwrap_or_default())
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            http.ssl_client_pkcs12_path = Some(pkcs12_path);
            let pw: String = Password::new()
                .with_prompt("Client PKCS#12 password (leave empty if none)")
                .allow_empty_password(true)
                .interact()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            if !pw.is_empty() {
                http.ssl_client_pkcs12_password = Some(pw);
            }
        }
        #[allow(clippy::unreachable)]
        _ => unreachable!(),
    }

    // Proxy settings prompt
    let use_proxy = Confirm::new()
        .with_prompt("Use an HTTP proxy?")
        .default(http.proxy_params.is_some())
        .interact()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;
    if use_proxy {
        let current = http.proxy_params.clone();
        let url_s: String = Input::new()
            .with_prompt("Proxy URL (e.g., http://host:port)")
            .with_initial_text(
                current
                    .as_ref()
                    .map(|p| p.url.as_str().to_owned())
                    .unwrap_or_default(),
            )
            .interact_text()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;
        let url = Url::parse(&url_s).map_err(|e| cli_error!("Invalid proxy URL: {e}"))?;

        let exclusion_list_s: String = Input::new()
            .with_prompt("Proxy exclusion list (comma-separated hosts) [optional]")
            .allow_empty(true)
            .with_initial_text(
                current
                    .as_ref()
                    .map(|p| p.exclusion_list.join(","))
                    .unwrap_or_default(),
            )
            .interact_text()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;
        let exclusion_list: Vec<String> = exclusion_list_s
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        let basic_auth_username: String = Input::new()
            .with_prompt("Proxy basic auth username [optional]")
            .allow_empty(true)
            .with_initial_text(
                current
                    .as_ref()
                    .and_then(|p| p.basic_auth_username.clone())
                    .unwrap_or_default(),
            )
            .interact_text()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;
        let basic_auth_password: String = Password::new()
            .with_prompt("Proxy basic auth password [optional]")
            .allow_empty_password(true)
            .interact()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;
        let custom_auth_header: String = Input::new()
            .with_prompt("Proxy custom auth header [optional]")
            .allow_empty(true)
            .with_initial_text(
                current
                    .as_ref()
                    .and_then(|p| p.custom_auth_header.clone())
                    .unwrap_or_default(),
            )
            .interact_text()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;

        http.proxy_params = Some(ProxyParams {
            url,
            basic_auth_username: if basic_auth_username.is_empty() {
                None
            } else {
                Some(basic_auth_username)
            },
            basic_auth_password: if basic_auth_password.is_empty() {
                None
            } else {
                Some(basic_auth_password)
            },
            custom_auth_header: if custom_auth_header.is_empty() {
                None
            } else {
                Some(custom_auth_header)
            },
            exclusion_list,
        });
    } else {
        http.proxy_params = None;
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
fn run_configure_wizard(mut config: ClientConfig) -> CosmianResult<()> {
    use cosmian_config_utils::get_default_conf_path;

    info!("Starting Cosmian CLI configuration wizard");

    // KMS
    configure_http("KMS", &mut config.kms_config.http_config)?;

    // KMS print_json
    let print_json: bool = Confirm::new()
        .with_prompt("Print KMS JSON KMIP requests/responses during operations?")
        .default(config.kms_config.print_json.unwrap_or(false))
        .interact()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;
    config.kms_config.print_json = Some(print_json);

    // Gmail API optional configuration
    let configure_gmail: bool = Confirm::new()
        .with_prompt("Configure Gmail API settings (for Google/Gmail integrations)?")
        .default(config.kms_config.gmail_api_conf.is_some())
        .interact()
        .map_err(|e| cli_error!("Prompt failed: {e}"))?;
    if configure_gmail {
        // Option to import from JSON file
        let import_from_json: bool = Confirm::new()
            .with_prompt("Import from a Google service account JSON file?")
            .default(true)
            .interact()
            .map_err(|e| cli_error!("Prompt failed: {e}"))?;
        if import_from_json {
            let path: String = Input::new()
                .with_prompt("Path to service account JSON file")
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            let contents = std::fs::read_to_string(path)
                .map_err(|e| cli_error!("Failed to read JSON file: {e}"))?;
            let conf: GmailApiConf = serde_json::from_str(&contents)
                .map_err(|e| cli_error!("Failed to parse Gmail JSON: {e}"))?;
            config.kms_config.gmail_api_conf = Some(conf);
        } else {
            let mut g = config
                .kms_config
                .gmail_api_conf
                .clone()
                .unwrap_or_else(|| GmailApiConf {
                    account_type: String::new(),
                    project_id: String::new(),
                    private_key_id: String::new(),
                    private_key: String::new(),
                    client_email: String::new(),
                    client_id: String::new(),
                    auth_uri: String::new(),
                    token_uri: String::new(),
                    auth_provider_x509_cert_url: String::new(),
                    client_x509_cert_url: String::new(),
                    universe_domain: String::new(),
                });
            g.account_type = Input::new()
                .with_prompt("Gmail account type")
                .with_initial_text(g.account_type)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.project_id = Input::new()
                .with_prompt("Gmail project_id")
                .with_initial_text(g.project_id)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.private_key_id = Input::new()
                .with_prompt("Gmail private_key_id")
                .with_initial_text(g.private_key_id)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.private_key = Password::new()
                .with_prompt("Gmail private_key")
                .with_confirmation("Confirm private_key", "Keys do not match")
                .interact()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.client_email = Input::new()
                .with_prompt("Gmail client_email")
                .with_initial_text(g.client_email)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.client_id = Input::new()
                .with_prompt("Gmail client_id")
                .with_initial_text(g.client_id)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.auth_uri = Input::new()
                .with_prompt("Gmail auth_uri")
                .with_initial_text(g.auth_uri)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.token_uri = Input::new()
                .with_prompt("Gmail token_uri")
                .with_initial_text(g.token_uri)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.auth_provider_x509_cert_url = Input::new()
                .with_prompt("Gmail auth_provider_x509_cert_url")
                .with_initial_text(g.auth_provider_x509_cert_url)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.client_x509_cert_url = Input::new()
                .with_prompt("Gmail client_x509_cert_url")
                .with_initial_text(g.client_x509_cert_url)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            g.universe_domain = Input::new()
                .with_prompt("Gmail universe_domain")
                .with_initial_text(g.universe_domain)
                .interact_text()
                .map_err(|e| cli_error!("Prompt failed: {e}"))?;
            config.kms_config.gmail_api_conf = Some(g);
        }
    } else {
        config.kms_config.gmail_api_conf = None;
    }

    // Save to default path explicitly (ignore env override to satisfy requirement)
    let default_path = get_default_conf_path(crate::config::CKMS_CONF_PATH)
        .map_err(|e| cli_error!("Failed to get default config path: {e}"))?;
    println!(
        "\nWriting configuration to default path: {}",
        default_path.display()
    );
    config
        .to_toml(
            default_path
                .to_str()
                .ok_or_else(|| cli_error!("Invalid default path encoding"))?,
        )
        .map_err(|e| cli_error!("Failed to write configuration: {e}"))?;

    info!("Configuration saved at {}", default_path.display());
    println!("Configuration saved. You're ready to go.");
    Ok(())
}
