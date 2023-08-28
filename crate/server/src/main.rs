use cosmian_kms_server::{
    bootstrap_server::start_bootstrap_server,
    config::{ClapConfig, ServerConfig},
    kms_server::start_kms_server,
    result::KResult,
};
use dotenvy::dotenv;
use tracing::error;
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
    let server_config = ServerConfig::try_from(&clap_config).await?;

    #[cfg(feature = "timeout")]
    info!("Feature Timeout enabled");
    #[cfg(feature = "insecure")]
    info!("Feature Insecure enabled");

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server(server_config, None)), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    if server_config.bootstrap_server_config.use_bootstrap_server {
        start_bootstrap_server(server_config).await
    } else {
        start_kms_server(server_config, None).await
    }
    .map_err(|e| {
        error!("FAILED STARTING: {e}");
        e
    })
}
