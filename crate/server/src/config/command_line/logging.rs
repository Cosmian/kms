use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct LoggingConfig {
    /// An alternative to setting the `RUST_LOG` environment variable.
    /// Setting this variable will override the `RUST_LOG` environment variable
    #[clap(long, env("KMS_RUST_LOG"), verbatim_doc_comment)]
    pub rust_log: Option<String>,

    /// The OTLP collector URL for gRPC
    /// (for instance, <http://localhost:4317>)
    /// If not set, the telemetry system will not be initialized
    #[clap(long, env("KMS_OTLP_URL"), verbatim_doc_comment)]
    pub otlp: Option<String>,

    /// Do not log to stdout
    #[clap(long, env("KMS_LOG_QUIET"), default_value = "false")]
    pub quiet: bool,

    #[cfg(not(target_os = "windows"))]
    #[clap(long, env("KMS_LOG_TO_SYSLOG"), default_value = "false")]
    /// Log to syslog
    pub log_to_syslog: bool,

    /// Enable metering in addition to tracing when telemetry is enabled
    #[clap(long, env("KMS_ENABLE_METERING"), default_value = "false")]
    pub enable_metering: bool,

    /// The name of the environment (development, test, production, etc.)
    /// This will be added to the telemetry data if telemetry is enabled
    #[clap(long, env("KMS_ENVIRONMENT"), default_value = "development")]
    pub environment: Option<String>,
}
