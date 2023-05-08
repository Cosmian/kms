use std::process;

use clap::{Parser, Subcommand};
use cosmian_kms_cli::{
    actions::{
        configure::entrypoint::NewDatabaseAction, cover_crypt::CoverCryptCommands,
        elliptic_curves::EllipticCurveCommands, permission::entrypoint::PermissionAction,
        sgx::entrypoint::SgxAction, symmetric::SymmetricCommands,
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
    Cc(CoverCryptCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Sym(SymmetricCommands),
    #[command(subcommand)]
    Permission(PermissionAction),
    Trust(SgxAction),
    NewDatabase(NewDatabaseAction),
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
    let conf = CliConf::load()?;

    match opts.command {
        CliCommands::Cc(action) => action.process(&conf).await?,
        CliCommands::Ec(action) => action.process(&conf).await?,
        CliCommands::Sym(action) => action.process(&conf).await?,
        CliCommands::Permission(action) => action.process(&conf).await?,
        CliCommands::Trust(action) => action.process(&conf).await?,
        CliCommands::NewDatabase(action) => action.process(&conf).await?,
    };

    Ok(())
}
