#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use clap::Parser;
use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
use cosmian_kms_k8s_plugin::{
    config::PluginConfig, kmsv2::key_management_service_server::KeyManagementServiceServer,
    service::KmsPluginService,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::info;

/// Cosmian KMS Provider Plugin for Kubernetes (KMS v2)
///
/// Exposes a Unix-domain gRPC server that kube-apiserver uses to encrypt and
/// decrypt Data Encryption Keys (DEKs) stored in etcd.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the plugin YAML configuration file.
    #[arg(short, long, env = "KMS_PLUGIN_CONFIG")]
    config: String,

    /// Log level filter (trace|debug|info|warn|error).
    #[arg(long, env = "KMS_PLUGIN_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let _logging_guards = cosmian_logger::tracing_init(&cosmian_logger::TracingConfig {
        rust_log: Some(args.log_level.clone()),
        service_name: "cosmian-kms-plugin".to_owned(),
        otlp: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .map(|url| cosmian_logger::TelemetryConfig {
                otlp_url: url,
                ..Default::default()
            }),
        ..Default::default()
    });

    let settings = PluginConfig::from_file(&args.config)?.cosmian_kms;

    info!(
        server_url = %settings.server_url,
        wrapping_key_uid = %settings.wrapping_key_uid,
        socket_path = %settings.socket_path,
        "Starting Cosmian KMS plugin"
    );

    // Build the KMS HTTP client from the plugin configuration.
    // `verified_cert` expects inline PEM content, not a file path: read the
    // CA cert file before constructing the client.
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

    let service = KmsPluginService::new(kms_client, settings.wrapping_key_uid);

    // Ensure socket directory exists.
    let socket_path = settings.socket_path;
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        std::fs::create_dir_all(parent)?;
        // Allow all users to traverse the directory (execute bit) so the
        // kube-apiserver process — which runs as UID 65532 in Kubernetes 1.29+
        // (distroless nonroot) — can reach the socket file.
        // Write access remains owner-only (no sticky bit needed; only root
        // creates files here).
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
    }

    // Remove stale socket file if present from a previous run.
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    // Allow any user to connect to the socket.
    // kube-apiserver runs as UID 65532 (distroless nonroot) in Kubernetes
    // 1.29+, so a root-owned 0o600 socket would silently block all gRPC
    // connections.  In production you can tighten this by chowning the socket
    // to the kube-apiserver UID/GID (65532) with mode 0o600, or by setting up
    // a dedicated group shared between the plugin and the apiserver.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path, "gRPC server listening on Unix socket");
    // Graceful shutdown on SIGTERM (systemd) or Ctrl-C.
    #[cfg(unix)]
    let shutdown = {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT, shutting down");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down");
                }
            }
        }
    };

    // Note: this binary is Unix-only (UnixListener, PermissionsExt); the
    // #[cfg(not(unix))] branch is intentionally absent.

    Server::builder()
        .add_service(KeyManagementServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;

    // Clean up socket on exit (best-effort, ignore errors).
    std::fs::remove_file(&socket_path).ok();

    Ok(())
}
