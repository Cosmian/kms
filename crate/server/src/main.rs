use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    kms_server::start_kms_server,
    result::KResult,
};
use dotenvy::dotenv;
use tracing::debug;
#[cfg(any(feature = "timeout", feature = "insecure"))]
use tracing::info;
#[cfg(feature = "timeout")]
use tracing::warn;
#[cfg(feature = "timeout")]
mod expiry;

use clap::Parser;
use clap_serde_derive::ClapSerde;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Config file
    #[arg(short, long = "config", default_value = "config.toml")]
    config_path: std::path::PathBuf,

    /// Rest of the arguments
    #[command(flatten)]
    pub config: <ClapConfig as ClapSerde>::Opt,
}

/// The main entrypoint of the program.
///
/// This function sets up the necessary environment variables and logging options,
/// then parses the command line arguments using [`ClapConfig::parse()`](https://docs.rs/clap/latest/clap/struct.ClapConfig.html#method.parse).
#[actix_web::main]
async fn main() -> KResult<()> {
    // Set up environment variables and logging options
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            "info,cosmian=info,cosmian_kms_server=info, \
             actix_web=info,sqlx::query=error,mysql=info",
        );
    }

    // Load variable from a .env file
    dotenv().ok();

    env_logger::init();

    let cfg_content = std::fs::read_to_string("./resources/config.toml").unwrap();
    println!("{cfg_content}");
    let clap_config =
        ClapConfig::from(toml::from_str::<<ClapConfig as ClapSerde>::Opt>(&cfg_content).unwrap())
            .merge_clap();

    // let mut args = Args::parse();
    // let clap_config = if let Ok(content) = std::fs::read_to_string(&args.config_path) {
    //     let cfg: ClapConfig = toml::from_str::<<ClapConfig as ClapSerde>::Opt>(&content)
    //         .unwrap()
    //         .into();
    //     cfg.merge(&mut args.config)
    //     // cfg
    // } else {
    //     // If there is no config file, return only config parsed from Clap
    //     ClapConfig::from(&mut args.config)
    // };

    // Instantiate a config object using the env variables and the args of the binary
    debug!("Command line config: {clap_config:#?}");

    // Parse the Server Config from the command line arguments
    let server_params = ServerParams::try_from(&clap_config).await?;

    #[cfg(feature = "timeout")]
    info!("Feature Timeout enabled");
    #[cfg(feature = "insecure")]
    info!("Feature Insecure enabled");

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server(server_params, None)), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    Box::pin(start_kms_server(server_params, None)).await?;

    Ok(())
}
