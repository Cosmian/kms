use cosmian_kms_server::{
    config::{ClapConfig, ServerConfig},
    result::KResult,
    start_kms_server,
};
use dotenvy::dotenv;
use tracing::info;
#[cfg(feature = "timeout")]
use tracing::warn;

#[cfg(feature = "timeout")]
mod expiry;

use clap::Parser;

#[actix_web::main]
async fn main() -> KResult<()> {
    if option_env!("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if option_env!("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "info,cosmian=debug,cosmian_kms_server=debug, \
             actix_web=debug,sqlx::query=error,mysql=debug",
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
        futures::future::select(Box::pin(start_kms_server(shared_config, None)), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    start_kms_server(server_config, None).await?;

    Ok(())
}
