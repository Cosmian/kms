use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    error::KmsError,
    kms_server::start_kms_server,
    result::KResult,
};
use dotenvy::dotenv;
#[cfg(feature = "timeout")]
use tracing::warn;
use tracing::{debug, info};
#[cfg(feature = "timeout")]
mod expiry;

const KMS_SERVER_CONF: &str = "/etc/cosmian_kms/server.toml";

/// The main entrypoint of the program.
///
/// This function sets up the necessary environment variables and logging options,
/// then parses the command line arguments using [`ClapConfig::parse()`](https://docs.rs/clap/latest/clap/struct.ClapConfig.html#method.parse).
#[actix_web::main]
async fn main() -> KResult<()> {
    // First operation to do is to load FIPS module if necessary.
    #[cfg(feature = "fips")]
    openssl::provider::Provider::load(None, "fips")?;

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

    let conf =
        PathBuf::from(std::env::var("COSMIAN_KMS_CONF").unwrap_or(KMS_SERVER_CONF.to_string()));
    let clap_config = if conf.exists() {
        _ = ClapConfig::parse(); // Do that do catch --help or --version even if we use a conf file

        info!(
            "Configuration file {conf:?} found. Command line arguments and env variables are \
             ignored."
        );

        let conf_content = std::fs::read_to_string(&conf).map_err(|e| {
            KmsError::ServerError(format!(
                "Cannot read kms server config at: {conf:?} - {e:?}"
            ))
        })?;
        toml::from_str(&conf_content).map_err(|e| {
            KmsError::ServerError(format!(
                "Cannot parse kms server config at: {conf:?} - {e:?}"
            ))
        })?
    } else {
        ClapConfig::parse()
    };

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
