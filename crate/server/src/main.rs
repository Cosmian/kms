use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    result::KResult,
    start_server,
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

/// The main entrypoint of the program.
///
/// This function sets up the necessary environment variables and logging options,
/// then parses the command line arguments using [`ClapConfig::parse()`](https://docs.rs/clap/latest/clap/struct.ClapConfig.html#method.parse).
///
/// After that, it starts the correct server based on
/// whether the bootstrap server should be used or not (using `start_bootstrap_server()` or `start_kms_server()`, respectively).
#[actix_web::main]
async fn main() -> KResult<()> {
    // Set up environment variables and logging options
    if option_env!("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    if option_env!("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "info,cosmian=info,cosmian_kms_server=info, \
             actix_web=info,sqlx::query=error,mysql=info",
        );
    }

    // Load variable from a .env file
    dotenv().ok();

    // Uncomment and remove `env-logger` dep when `env_logger` is
    // finally updated in tracing-log crate.
    // cosmian_logger::reexport::tracing_log::env_logger::init();
    env_logger::init();

    // Instantiate a config object using the env variables and the args of the binary
    let clap_config = ClapConfig::parse();
    debug!("Command line config: {:#?}", clap_config);

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
        futures::future::select(start_server(server_params, None), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    start_server(server_params, None).await?;

    Ok(())
}
