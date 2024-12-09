use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_config_utils::ConfigUtils;
use cosmian_findex_cli::reexports::cosmian_findex_client::FindexRestClient;
use cosmian_kms_cli::{KmsActions, reexport::cosmian_kms_client::KmsClient};
use cosmian_logger::log_init;
use tracing::{info, trace};

use crate::{
    actions::{findex::FindexActions, markdown::MarkdownAction},
    cli_error,
    config::ClientConf,
    error::result::CosmianResult,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Configuration file location
    ///
    /// This is an alternative to the env variable `KMS_CLI_CONF`.
    /// Takes precedence over `KMS_CLI_CONF` env variable.
    #[arg(short, long)]
    conf: Option<PathBuf>,

    #[command(subcommand)]
    pub command: CliCommands,

    /// The URL of the KMS
    #[arg(long, env = "KMS_DEFAULT_URL", action)]
    pub kms_url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub kms_accept_invalid_certs: Option<bool>,

    /// Output the KMS JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long, default_value = "false")]
    pub kms_print_json: bool,

    /// The URL of the Findex server
    #[arg(long, env = "FINDEX_SERVER_DEFAULT_URL", action)]
    pub findex_url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub findex_accept_invalid_certs: Option<bool>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CliCommands {
    /// Handle KMS actions
    #[command(subcommand)]
    Kms(KmsActions),
    /// Handle Findex server actions
    #[command(subcommand)]
    FindexServer(FindexActions),
    /// Action to auto-generate doc in Markdown format
    /// Run `cargo run --bin cosmian -- markdown documentation/docs/cli/main_commands.md`
    #[clap(hide = true)]
    Markdown(MarkdownAction),
}

/// Main function for the CKMS CLI application.
///
/// This function initializes logging, parses command-line arguments, and executes the appropriate
/// command based on the provided arguments. It supports various subcommands for interacting with
/// the CKMS, such as login, logout, locating objects, and more.
///
/// # Errors
///
/// This function will return an error if:
/// - The logging initialization fails.
/// - The command-line arguments cannot be parsed.
/// - The configuration file cannot be located or loaded.
/// - Any of the subcommands fail during their execution.
#[allow(clippy::future_not_send)]
pub async fn cosmian_main() -> CosmianResult<()> {
    log_init(None);
    info!("Starting Cosmian CLI");
    let cli = Cli::parse();

    let conf_path = ClientConf::location(cli.conf)?;
    let mut conf = ClientConf::from_toml(&conf_path)?;

    // Override the configuration with the CLI arguments
    let mut has_been_overridden = false;
    if let Some(url) = cli.kms_url.clone() {
        conf.kms_config.http_config.server_url = url;
        has_been_overridden = true;
    }
    if let Some(accept_invalid_certs) = cli.kms_accept_invalid_certs {
        conf.kms_config.http_config.accept_invalid_certs = accept_invalid_certs;
        has_been_overridden = true;
    }
    if let Some(url) = cli.findex_url.clone() {
        if let Some(findex_conf) = conf.findex_config.as_mut() {
            findex_conf.http_config.server_url = url;
            has_been_overridden = true;
        }
    }
    if let Some(accept_invalid_certs) = cli.findex_accept_invalid_certs {
        if let Some(findex_conf) = conf.findex_config.as_mut() {
            findex_conf.http_config.accept_invalid_certs = accept_invalid_certs;
            has_been_overridden = true;
        }
    }
    conf.kms_config.print_json = Some(cli.kms_print_json);
    if has_been_overridden {
        conf.to_toml(&conf_path)?;
    }

    trace!("Configuration: {conf:?}");

    // Instantiate the KMS and Findex clients
    let kms_rest_client = KmsClient::new(conf.kms_config)?;

    match cli.command {
        CliCommands::Markdown(action) => {
            let command = <Cli as CommandFactory>::command();
            action.process(&command)?;
            return Ok(())
        }
        CliCommands::Kms(kms_actions) => {
            kms_actions.process(&kms_rest_client).await?;
        }
        CliCommands::FindexServer(findex_actions) => {
            let findex_config = conf.findex_config.ok_or_else(|| {
                cli_error!("Findex server configuration is missing in the configuration file")
            })?;
            let findex_rest_client = FindexRestClient::new(findex_config)?;
            findex_actions
                .run(findex_rest_client, &kms_rest_client)
                .await?;
        }
    }

    Ok(())
}
