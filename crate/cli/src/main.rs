use clap::{crate_description, crate_name, crate_version, StructOpt};
use cosmian_kms_cli::{
    actions::{
        abe::{cover_crypt::entrypoint::CoverCryptAction, gpsw::entrypoint::GpswAction},
        configure::entrypoint::ConfigureAction,
        permission::entrypoint::PermissionAction,
        sgx::entrypoint::SgxAction,
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
    Gpsw(GpswAction),
    #[clap(subcommand)]
    Cc(CoverCryptAction),
    #[clap(subcommand)]
    Permission(PermissionAction),
    Trust(SgxAction),
    Configure(ConfigureAction),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let opts = CliCommands::parse();
    let conf = CliConf::load()?;

    match opts {
        CliCommands::Gpsw(action) => action.process(&conf).await?,
        CliCommands::Cc(action) => action.process(&conf).await?,
        CliCommands::Permission(action) => action.process(&conf).await?,
        CliCommands::Trust(action) => action.process(&conf).await?,
        CliCommands::Configure(action) => action.process(&conf).await?,
    };

    Ok(())
}
