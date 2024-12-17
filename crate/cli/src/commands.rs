use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_config_utils::ConfigUtils;
use cosmian_findex_cli::{CoreFindexActions, reexports::cosmian_findex_client::FindexRestClient};
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
    /// This is an alternative to the env variable `COSMIAN_CLI_CONF_PATH`.
    /// Takes precedence over `COSMIAN_CLI_CONF_PATH` env variable.
    #[arg(short, env = "COSMIAN_CLI_CONF_PATH", long)]
    conf_path: Option<PathBuf>,

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
    pub kms_accept_invalid_certs: bool,

    /// Output the KMS JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long)]
    pub kms_print_json: bool,

    /// The URL of the Findex server
    #[arg(long, env = "FINDEX_SERVER_DEFAULT_URL", action)]
    pub findex_url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub findex_accept_invalid_certs: bool,
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
#[allow(clippy::future_not_send, clippy::cognitive_complexity)]
pub async fn cosmian_main() -> CosmianResult<()> {
    log_init(None);
    info!("Starting Cosmian CLI");
    let cli = Cli::parse();

    let conf_path = ClientConf::location(cli.conf_path)?;
    let mut config = ClientConf::from_toml(&conf_path)?;

    // Handle KMS configuration
    if let Some(url) = cli.kms_url.clone() {
        config.kms_config.http_config.server_url = url;
    }
    if cli.kms_accept_invalid_certs {
        config.kms_config.http_config.accept_invalid_certs = true;
    }
    config.kms_config.print_json = Some(cli.kms_print_json);

    // Handle Findex server configuration
    if let Some(findex_config) = config.findex_config.as_mut() {
        if let Some(url) = cli.findex_url.clone() {
            findex_config.http_config.server_url = url;
        }
        if cli.findex_accept_invalid_certs {
            findex_config.http_config.accept_invalid_certs = true;
        }
    }

    trace!("Configuration: {config:?}");

    // Instantiate the KMS client
    let mut kms_rest_client = KmsClient::new(config.kms_config.clone())?;

    match &cli.command {
        CliCommands::Markdown(action) => {
            let command = <Cli as CommandFactory>::command();
            action.process(&command)?;
            return Ok(())
        }
        CliCommands::Kms(kms_actions) => {
            kms_actions.process(&mut kms_rest_client).await?;
            config.kms_config = kms_rest_client.config.clone();
        }
        CliCommands::FindexServer(findex_actions) => {
            let findex_config = config.findex_config.as_ref().ok_or_else(|| {
                cli_error!("Findex server configuration is missing in the configuration file")
            })?;
            let mut findex_rest_client = FindexRestClient::new(findex_config.clone())?;
            findex_actions
                .run(&mut findex_rest_client, &kms_rest_client)
                .await?;
            config.findex_config = Some(findex_rest_client.config.clone());
        }
    }

    // Save the configuration
    match cli.command {
        CliCommands::Kms(KmsActions::Login(_) | KmsActions::Logout(_)) => {
            config.to_toml(&conf_path)?;
            info!("Saving configuration to: {conf_path:?}");
        }
        CliCommands::FindexServer(FindexActions::Findex(
            CoreFindexActions::Login(_) | CoreFindexActions::Logout(_),
        )) => {
            config.to_toml(&conf_path)?;
            info!("Saving configuration to: {conf_path:?}");
        }
        _ => {}
    }

    Ok(())
}
