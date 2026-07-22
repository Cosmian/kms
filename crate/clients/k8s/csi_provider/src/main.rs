#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use clap::Parser;
use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
use cosmian_kms_csi_provider::{
    config::CsiProviderConfig, service::CsiProviderService,
    v1alpha1::csi_driver_provider_server::CsiDriverProviderServer,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::info;

/// Cosmian KMS Secrets Store CSI Driver Provider
///
/// Exposes a Unix-domain gRPC server that the Kubernetes Secrets Store CSI
/// Driver calls to fetch secrets from the Cosmian KMS and mount them as files
/// in pod volumes.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the provider YAML configuration file.
    #[arg(short, long, env = "KMS_CSI_CONFIG")]
    config: String,

    /// Log level filter (trace|debug|info|warn|error).
    #[arg(long, env = "KMS_CSI_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let _logging_guards = cosmian_logger::tracing_init(&cosmian_logger::TracingConfig {
        rust_log: Some(args.log_level.clone()),
        service_name: "cosmian-kms-csi-provider".to_owned(),
        otlp: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .map(|url| cosmian_logger::TelemetryConfig {
                otlp_url: url,
                ..Default::default()
            }),
        ..Default::default()
    });

    let settings = CsiProviderConfig::from_file(&args.config)?.cosmian_kms;

    info!(
        server_url = %settings.server_url,
        socket_path = %settings.socket_path,
        "Starting Cosmian KMS CSI provider"
    );

    let verified_cert = settings
        .ca_cert
        .as_deref()
        .map(std::fs::read_to_string)
        .transpose()?;

    let http_config = HttpClientConfig {
        server_url: settings.server_url,
        access_token: settings.api_key,
        tls_client_pem_cert_path: settings.tls_cert,
        tls_client_pem_key_path: settings.tls_key,
        verified_cert,
        ..HttpClientConfig::default()
    };
    let kms_client = KmsClient::new_with_config(KmsClientConfig {
        http_config,
        ..KmsClientConfig::default()
    })?;

    let service = CsiProviderService::new(kms_client);

    // Create the socket directory with mode 0700 to prevent TOCTOU races
    // before binding.
    let socket_path = settings.socket_path;
    if let Some(dir) = std::path::Path::new(&socket_path).parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Remove a stale socket file if one exists from a previous run.
    drop(std::fs::remove_file(&socket_path));

    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

    info!(%socket_path, "CSI provider listening");

    Server::builder()
        .add_service(CsiDriverProviderServer::new(service))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::warn!("Failed to listen for SIGINT; shutting down anyway");
            }
            info!("Received SIGINT, shutting down CSI provider");
        })
        .await?;

    Ok(())
}
