use std::process;

use clap::{CommandFactory, Parser};
use cosmian_kms_cli::{
    commands::{Cli, CliCommands},
    config::CliConf,
    error::CliError,
};
use cosmian_logger::log_utils::log_init;

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
        CliCommands::GetAttributes(action) => action.process(&kms_rest_client).await?,
        CliCommands::Login(action) => action.process().await?,
        CliCommands::Logout(action) => action.process().await?,
        _ => {
            println!("Unknown command");
        }
    };

    Ok(())
}
