use std::pin::Pin;

use cosmian_kms_server::{
    bootstrap_server::start_bootstrap_server,
    config::{ClapConfig, ServerParams},
    kms_server::start_kms_server,
    result::KResult,
};
use dotenvy::dotenv;
use futures::Future;
use tracing::debug;
#[cfg(any(feature = "timeout", feature = "insecure"))]
use tracing::info;
#[cfg(feature = "timeout")]
use tracing::warn;
#[cfg(feature = "timeout")]
mod expiry;

use clap::Parser;

#[tokio::main]
async fn main() -> KResult<()> {
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

    env_logger::init();

    // Instantiate a config object using the env variables and the args of the binary
    let clap_config = ClapConfig::parse();
    debug!("Command line config: {:#?}", clap_config);

    // Parse the Server Config from the command line arguments
    let server_config = ServerParams::try_from(&clap_config).await?;

    #[cfg(feature = "timeout")]
    info!("Feature Timeout enabled");
    #[cfg(feature = "insecure")]
    info!("Feature Insecure enabled");

    fn start_correct_server(
        server_config: ServerParams,
    ) -> Pin<Box<dyn Future<Output = KResult<()>>>> {
        if server_config.bootstrap_server_config.use_bootstrap_server {
            Box::pin(start_bootstrap_server(server_config))
        } else {
            Box::pin(start_kms_server(server_config, None))
        }
    }

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(start_correct_server(server_config), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    start_correct_server(server_config).await?;

    Ok(())
}
