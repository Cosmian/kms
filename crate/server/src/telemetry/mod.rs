use clap::Args;
use serde::{Deserialize, Serialize};
use tracing::{dispatcher, info, span, Dispatch};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

use crate::{config::ClapConfig, result::KResult};

mod otlp;

#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TelemetryConfig {
    /// The OTLP collector URL
    /// (for instance, <http://localhost:4317>)
    #[clap(long, env("KMS_OTLP_URL"), verbatim_doc_comment)]
    pub otlp: Option<String>,
    /// Do not log to stdout
    #[clap(long, env("KMS_LOG_QUIET"), default_value = "false")]
    pub quiet: bool,
}

/// Initialize the telemetry system
///
/// # Arguments
///
/// * `clap_config` - The `ClapConfig` object containing the telemetry configuration
///
/// # Errors
///
/// Returns an error if there is an issue initializing the telemetry system.
pub fn initialize_telemetry(clap_config: &ClapConfig) -> KResult<()> {
    let config = &clap_config.telemetry;
    let (filter, _reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::from_default_env());

    // The subscriber type is so convoluted, it is impossible to simplify this code
    if let Some(url) = &config.otlp {
        let tracer = otlp::init_otlp_tracer(url.to_owned())?;
        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        if config.quiet {
            let subscriber = Registry::default().with(filter).with(telemetry);
            dispatcher::set_global_default(Dispatch::new(subscriber))?;
        } else {
            let subscriber = Registry::default().with(filter).with(telemetry).with(
                tracing_subscriber::fmt::layer()
                    .with_level(true)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_file(true)
                    .with_ansi(true)
                    .compact(),
            );
            dispatcher::set_global_default(Dispatch::new(subscriber))?;
        }
    } else if !config.quiet {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .with_ansi(true)
            .compact()
            .init();
    };

    // We need to create a span to be able to log the initialization
    // because, for an unknown reason, the first log message is not displayed
    // in the main function
    let span = span!(tracing::Level::INFO, "start");
    let _guard = span.enter();
    info!(
        "Telemetry initialized. Server starting with config {:#?}",
        clap_config
    );

    Ok(())
}
