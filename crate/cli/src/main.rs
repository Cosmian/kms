use std::process;

use clap::{CommandFactory, Parser, Subcommand};
use cosmian_kms_cli::{
    actions::{
        access::AccessAction,
        bootstrap::BootstrapServerAction,
        certificates::CertificatesCommands,
        cover_crypt::CovercryptCommands,
        elliptic_curves::EllipticCurveCommands,
        login::LoginAction,
        logout::LogoutAction,
        markdown::MarkdownAction,
        new_database::NewDatabaseAction,
        shared::{GetAttributesAction, LocateObjectsAction},
        symmetric::SymmetricCommands,
        verify::TeeAction,
        version::ServerVersionAction,
    },
    config::CliConf,
    error::CliError,
};
use cosmian_logger::log_utils::log_init;
use tokio::task::spawn_blocking;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,
}

#[derive(Subcommand)]
enum CliCommands {
    #[command(subcommand)]
    AccessRights(AccessAction),
    BootstrapStart(BootstrapServerAction),
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    GetAttributes(GetAttributesAction),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    Verify(TeeAction),
    Login(LoginAction),
    Logout(LogoutAction),
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
    log_init("");

    let opts = Cli::parse();
    let conf = CliConf::load()?;

    if let CliCommands::Verify(action) = opts.command {
        action.process(&conf).await?;
        return Ok(())
    }

    if let CliCommands::BootstrapStart(action) = opts.command {
        let bootstrap_rest_client = spawn_blocking(move || conf.initialize_bootstrap_client())
            .await
            .map_err(|e| CliError::Default(e.to_string()))??;
        action.process(&bootstrap_rest_client).await?;
        return Ok(())
    }

    if let CliCommands::Markdown(action) = opts.command {
        let command = <Cli as CommandFactory>::command();
        action.process(&command).await?;
        return Ok(())
    }

    let kms_rest_client = conf.initialize_kms_client()?;

    match opts.command {
        CliCommands::Locate(action) => action.process(&kms_rest_client).await?,
        CliCommands::Cc(action) => action.process(&kms_rest_client).await?,
        CliCommands::Ec(action) => action.process(&kms_rest_client).await?,
        CliCommands::Sym(action) => action.process(&kms_rest_client).await?,
        CliCommands::AccessRights(action) => action.process(&kms_rest_client).await?,
        CliCommands::Certificates(action) => action.process(&kms_rest_client).await?,
        CliCommands::NewDatabase(action) => action.process(&kms_rest_client).await?,
        CliCommands::ServerVersion(action) => action.process(&kms_rest_client).await?,
        CliCommands::BootstrapStart(_) | CliCommands::Verify(_) => {}
        CliCommands::GetAttributes(action) => action.process(&kms_rest_client).await?,
        CliCommands::Login(action) => action.process().await?,
        CliCommands::Logout(action) => action.process().await?,
        _ => {
            println!("Error");
        }
    };

    Ok(())
}
