use std::{path::PathBuf, process};

use clap::{CommandFactory, Parser, Subcommand};
#[cfg(not(feature = "fips"))]
use cosmian_kms_cli::actions::cover_crypt::CovercryptCommands;
use cosmian_kms_cli::{
    actions::{
        access::AccessAction,
        certificates::CertificatesCommands,
        elliptic_curves::EllipticCurveCommands,
        login::LoginAction,
        logout::LogoutAction,
        markdown::MarkdownAction,
        new_database::NewDatabaseAction,
        rsa::RsaCommands,
        shared::{GetAttributesAction, LocateObjectsAction},
        symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    config::CliConf,
    error::CliError,
};

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
    GetAttributes(GetAttributesAction),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Login(LoginAction),
    Logout(LogoutAction),
    #[clap(hide = true)]
    Markdown(MarkdownAction),
}

#[tokio::main]
async fn main() {
    if let Some(err) = main_().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}

async fn main_() -> Result<(), CliError> {
    // Set up environment variables and logging options
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            "info,cosmian=info,cosmian_kms_cli=info, actix_web=info,sqlx::query=error,mysql=info",
        );
    }

    env_logger::init();

    let opts = Cli::parse();

    if let CliCommands::Markdown(action) = opts.command {
        let command = <Cli as CommandFactory>::command();
        action.process(&command).await?;
        return Ok(())
    }

    let conf_path = CliConf::location(opts.conf)?;

    match opts.command {
        CliCommands::Login(action) => action.process(&conf_path).await?,
        CliCommands::Logout(action) => action.process(&conf_path).await?,
        command => {
            let conf = CliConf::load(&conf_path)?;
            let kms_rest_client = conf.initialize_kms_client()?;

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
                CliCommands::GetAttributes(action) => action.process(&kms_rest_client).await?,
                _ => {
                    println!("Error: unexpected command");
                }
            }
        }
    }

    Ok(())
}
