use clap::Parser;
use cosmian_kms_k8s_operator::{
    config::{Cli, Command},
    error::OperatorError,
    inject, print_crd, serve,
};

#[tokio::main]
async fn main() -> Result<(), OperatorError> {
    let _logging_guards = cosmian_logger::tracing_init(&cosmian_logger::TracingConfig {
        service_name: std::env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "cosmian-kms-operator".to_owned()),
        otlp: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .map(|url| cosmian_logger::TelemetryConfig {
                otlp_url: url,
                ..Default::default()
            }),
        ..Default::default()
    });

    let cli = Cli::parse();

    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Inject(args) => inject(args).await,
        Command::Crd => print_crd(),
    }
}
