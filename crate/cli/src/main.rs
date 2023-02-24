use clap::Parser;
use cosmian_kms_cli::{
    actions::{
        abe::cover_crypt::entrypoint::CoverCryptAction, configure::entrypoint::ConfigureAction,
        permission::entrypoint::PermissionAction, sgx::entrypoint::SgxAction,
    },
    config::CliConf,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum CliCommands {
    #[command(subcommand)]
    Cc(CoverCryptAction),
    #[command(subcommand)]
    Permission(PermissionAction),
    Trust(SgxAction),
    Configure(ConfigureAction),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let opts = CliCommands::parse();
    let conf = CliConf::load()?;

    match opts {
        CliCommands::Cc(action) => action.process(&conf).await?,
        CliCommands::Permission(action) => action.process(&conf).await?,
        CliCommands::Trust(action) => action.process(&conf).await?,
        CliCommands::Configure(action) => action.process(&conf).await?,
    };

    Ok(())
}
