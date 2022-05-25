use cosmian_kms_server::config::{init_config, Config};
#[cfg(any(feature = "dev", test, feature = "demo_timeout"))]
use cosmian_kms_server::start_kms_server;
#[cfg(all(not(feature = "dev"), not(feature = "demo_timeout"), not(test)))]
use cosmian_kms_server::start_secure_kms_server;
use dotenv::dotenv;
#[cfg(not(feature = "demo_timeout"))]
use tracing::info;
#[cfg(feature = "demo_timeout")]
use tracing::warn;
use twelf::Layer;

#[cfg(feature = "demo_timeout")]
mod expiry;

#[actix_web::main]
async fn main() -> eyre::Result<()> {
    if option_env!("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if option_env!("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "debug, actix_web=debug,hyper=info,reqwest=info,sqlx::query=error,mysql=debug",
        );
    }

    // Load variable from a .env file
    dotenv().ok();

    env_logger::init();

    // Instanciate a config object using the env variables and the args of the binary
    let matches = clap::Command::new("cosmian_kms_server")
        .args(&Config::clap_args())
        .get_matches();

    let conf = Config::with_layers(&[Layer::Env(Some("KMS_".to_string())), Layer::Clap(matches)])?;

    init_config(&conf).await?;

    // Demo version only enables the HTTP server
    #[cfg(feature = "demo_timeout")]
    {
        warn!("This is a demo version, the server will stop in 3 months");
        let demo = actix_rt::spawn(expiry::demo_timeout());
        futures::future::select(Box::pin(start_kms_server()), demo).await;
    }

    #[cfg(not(feature = "demo_timeout"))]
    {
        // Dev version only enables the HTTP server
        #[cfg(any(feature = "dev", test))]
        {
            info!("This is a dev environment version using HTTP only");
            start_kms_server().await?;
        }
        // Default (production & staging) version only enables the HTTPS server
        #[cfg(all(not(feature = "dev"), not(test)))]
        {
            #[cfg(feature = "staging")]
            info!("This is the staging environment version using HTTPS only");
            #[cfg(not(feature = "staging"))]
            info!("This is the production environment version using HTTPS only");
            start_secure_kms_server().await?;
        }
    }
    Ok(())
}
