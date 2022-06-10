use clap::{crate_description, crate_name, crate_version, StructOpt};
use cosmian_kms_cli::{
    actions::{
        abe::entrypoint::AbeAction, cover_crypt::entrypoint::CoverCryptAction,
        permission::entrypoint::PermissionAction, sgx::entrypoint::SgxAction,
    },
    config::CliConf,
};

#[derive(StructOpt, Debug)]
#[structopt(
    name = crate_name!(),
    version = crate_version!(),
    about = crate_description!()
)]
enum CliCommands {
    #[clap(subcommand)]
    Abe(AbeAction),
    #[clap(subcommand)]
    Cc(CoverCryptAction),
    #[clap(subcommand)]
    Permission(PermissionAction),
    Trust(SgxAction),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let conf = CliConf::load()?;
    let opts = CliCommands::parse();

    match opts {
        CliCommands::Abe(action) => action.process(&conf).await?,
        CliCommands::Cc(action) => action.process(&conf).await?,
        CliCommands::Permission(action) => action.process(&conf).await?,
        CliCommands::Trust(action) => action.process(&conf).await?,
    };

    Ok(())
}
