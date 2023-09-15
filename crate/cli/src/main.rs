use std::process;

use clap::{Parser, Subcommand};
use cosmian_kms_cli::{
    actions::{
        access::AccessAction, bootstrap::BootstrapServerAction, cover_crypt::CovercryptCommands,
        elliptic_curves::EllipticCurveCommands, new_database::NewDatabaseAction,
        shared::LocateObjectsAction, symmetric::SymmetricCommands, version::ServerVersionAction,
    },
    config::CliConf,
    error::CliError,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommands,
}

#[derive(Subcommand)]
enum CliCommands {
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    #[command(subcommand)]
    AccessRights(AccessAction),
    Locate(LocateObjectsAction),
    NewDatabase(NewDatabaseAction),
    ServerVersion(ServerVersionAction),
    BootstrapStart(BootstrapServerAction),
}

#[tokio::main]
async fn main() {
    if let Some(err) = main_().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}

async fn main_() -> Result<(), CliError> {
    let opts = Cli::parse();
    let (kms_rest_client, bootstrap_rest_client) = CliConf::load()?;

    match opts.command {
        CliCommands::Locate(action) => action.process(&kms_rest_client).await?,
        CliCommands::Cc(action) => action.process(&kms_rest_client).await?,
        CliCommands::Ec(action) => action.process(&kms_rest_client).await?,
        CliCommands::Sym(action) => action.process(&kms_rest_client).await?,
        CliCommands::AccessRights(action) => action.process(&kms_rest_client).await?,
        CliCommands::NewDatabase(action) => action.process(&kms_rest_client).await?,
        CliCommands::ServerVersion(action) => action.process(&kms_rest_client).await?,
        CliCommands::BootstrapStart(action) => action.process(&bootstrap_rest_client).await?,
    };

    Ok(())
}
