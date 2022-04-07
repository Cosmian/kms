use clap::StructOpt;
use kms_cli::actions::abe::entrypoint::AbeAction;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "kms-cli",
    version = "0.1",
    about = "The Cosmian KMS command line"
)]
enum CliCommands {
    #[clap(subcommand)]
    Abe(AbeAction),
}

use kms_cli::config::CliConf;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let conf = CliConf::load()?;
    let opts = CliCommands::parse();

    match opts {
        CliCommands::Abe(action) => action.process(&conf).await?,
    };

    Ok(())
}
