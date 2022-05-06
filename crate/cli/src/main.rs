use clap::StructOpt;
use cosmian_kms_cli::{
    actions::{abe::entrypoint::AbeAction, permission::entrypoint::PermissionAction},
    config::CliConf,
};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "cosmian_kms_cli",
    version = "0.1",
    about = "The Cosmian KMS command line"
)]
enum CliCommands {
    #[clap(subcommand)]
    Abe(AbeAction),
    #[clap(subcommand)]
    Permission(PermissionAction),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let conf = CliConf::load()?;
    let opts = CliCommands::parse();

    match opts {
        CliCommands::Abe(action) => action.process(&conf).await?,
        CliCommands::Permission(action) => action.process(&conf).await?,
    };

    Ok(())
}
