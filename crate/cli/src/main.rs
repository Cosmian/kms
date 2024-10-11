use std::{path::PathBuf, process};

use clap::{CommandFactory, Parser, Subcommand};
#[cfg(not(feature = "fips"))]
use cosmian_kms_cli::actions::cover_crypt::CovercryptCommands;
use cosmian_kms_cli::{
    actions::{
        access::AccessAction, attributes::AttributesCommands, certificates::CertificatesCommands,
        elliptic_curves::EllipticCurveCommands, google::GoogleCommands, login::LoginAction,
        logout::LogoutAction, markdown::MarkdownAction, new_database::NewDatabaseAction,
        rsa::RsaCommands, shared::LocateObjectsAction, symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    error::result::CliResult,
};
use cosmian_kms_client::ClientConf;
use cosmian_logger::log_utils::log_init;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,

    /// Configuration file location
    ///
    /// This is an alternative to the env variable `KMS_CLI_CONF`.
    /// Takes precedence over `KMS_CLI_CONF` env variable.
    #[arg(short, long)]
    conf: Option<PathBuf>,

    /// The URL of the KMS
    #[arg(long, action)]
    pub(crate) url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub(crate) accept_invalid_certs: Option<bool>,

    /// Output the JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long, default_value = "false")]
    pub(crate) json: bool,
}

#[derive(Subcommand)]
enum CliCommands {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[cfg(not(feature = "fips"))]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Login(LoginAction),
    Logout(LogoutAction),

    /// Action to auto-generate doc in Markdown format
    /// Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`
    #[clap(hide = true)]
    Markdown(MarkdownAction),

    #[command(subcommand)]
    Google(GoogleCommands),
}

#[tokio::main]
async fn main() {
    if let Some(err) = main_().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}

async fn main_() -> CliResult<()> {
    log_init(None);
    let opts = Cli::parse();

    if let CliCommands::Markdown(action) = opts.command {
        let command = <Cli as CommandFactory>::command();
        action.process(&command)?;
        return Ok(())
    }

    let conf_path = ClientConf::location(opts.conf)?;

    match opts.command {
        CliCommands::Login(action) => action.process(&conf_path).await?,
        CliCommands::Logout(action) => action.process(&conf_path)?,

        command => {
            let conf = ClientConf::load(&conf_path)?;
            let kms_rest_client = conf.initialize_kms_client(
                opts.url.as_deref(),
                opts.accept_invalid_certs,
                opts.json,
            )?;

            match command {
                CliCommands::Locate(action) => action.process(&kms_rest_client).await?,
                #[cfg(not(feature = "fips"))]
                CliCommands::Cc(action) => action.process(&kms_rest_client).await?,
                CliCommands::Ec(action) => action.process(&kms_rest_client).await?,
                CliCommands::Rsa(action) => action.process(&kms_rest_client).await?,
                CliCommands::Sym(action) => action.process(&kms_rest_client).await?,
                CliCommands::AccessRights(action) => action.process(&kms_rest_client).await?,
                CliCommands::Certificates(action) => action.process(&kms_rest_client).await?,
                CliCommands::NewDatabase(action) => action.process(&kms_rest_client).await?,
                CliCommands::ServerVersion(action) => action.process(&kms_rest_client).await?,
                CliCommands::Attributes(action) => action.process(&kms_rest_client).await?,
                CliCommands::Google(action) => action.process(&conf_path, &kms_rest_client).await?,
                _ => {
                    tracing::error!("unexpected command");
                }
            }
        }
    }

    Ok(())
}
