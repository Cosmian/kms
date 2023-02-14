use cosmian_kms_server::{
    config::{init_config, Config},
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
async fn main() -> eyre::Result<()> {
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
    let conf = Config::parse();

    init_config(&conf).await?;

    info!("Enabled features:");
    #[cfg(feature = "timeout")]
    info!("- Timeout");
    #[cfg(feature = "insecure")]
    info!("- Insecure");

    #[cfg(feature = "timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server()), demo).await;
    }

    // Start the KMS
    #[cfg(not(feature = "timeout"))]
    start_kms_server().await?;

    Ok(())
}
