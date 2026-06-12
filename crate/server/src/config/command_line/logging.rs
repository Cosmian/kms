use std::path::PathBuf;

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
#[must_use]
pub fn get_default_rolling_log_dir() -> PathBuf {
    PathBuf::from("/var/log/")
}

#[cfg(target_os = "windows")]
#[must_use]
pub fn get_default_rolling_log_dir() -> PathBuf {
    // Use %LOCALAPPDATA%\Cosmian KMS Server which is guaranteed to exist and is
    // writable by standard (non-admin) users.  Falls back to ProgramData only
    // when the environment variable is missing (e.g. LocalSystem service account).
    std::env::var("LOCALAPPDATA").map_or_else(
        |_| PathBuf::from(r"C:\ProgramData\Cosmian KMS Server"),
        |localappdata| PathBuf::from(localappdata).join("Cosmian KMS Server"),
    )
}

#[cfg(target_os = "macos")]
#[must_use]
pub fn get_default_rolling_log_dir() -> PathBuf {
    // Use ~/Library/Logs/ which is the standard per-user log directory on macOS
    // and is writable without root.
    std::env::var_os("HOME").map_or_else(
        || PathBuf::from("/tmp"),
        |home| PathBuf::from(home).join("Library/Logs"),
    )
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct LoggingConfig {
    /// An alternative to setting the `RUST_LOG` environment variable.
    /// Setting this variable will override the `RUST_LOG` environment variable
    #[clap(long, env("KMS_RUST_LOG"), verbatim_doc_comment)]
    pub rust_log: Option<String>,

    /// The OTLP collector URL for gRPC
    /// (for instance, <https://localhost:4317>)
    /// If not set, the telemetry system will not be initialized.
    /// Must use https:// in production.
    /// Use --otlp-allow-insecure to permit plaintext http:// connections.
    #[clap(long, env("KMS_OTLP_URL"), verbatim_doc_comment)]
    pub otlp: Option<String>,

    /// Allow insecure (plaintext HTTP) OTLP connections.
    /// WARNING: Enabling this exposes telemetry data (including encryption
    /// operation metadata) over an unencrypted channel.
    /// Only use for development or when the collector is on localhost.
    #[clap(long, env("KMS_OTLP_ALLOW_INSECURE"), default_value = "false")]
    pub otlp_allow_insecure: bool,

    /// Do not log to stdout
    #[clap(long, env("KMS_LOG_QUIET"), default_value = "false")]
    pub quiet: bool,

    #[cfg(not(target_os = "windows"))]
    #[clap(long, env("KMS_LOG_TO_SYSLOG"), default_value = "false")]
    /// Log to syslog
    pub log_to_syslog: bool,

    /// The directory for daily rolling logs: <rolling_log_name>.YYYY-MM-DD.
    /// File logging is disabled unless this option is explicitly set.
    /// Suggested paths:
    ///   Linux: /var/log/
    ///   Windows: C:\Users\<username>\AppData\Local\Cosmian KMS Server
    ///   macOS: ~/Library/Logs/
    ///
    /// WARNING: Windows environment variables (e.g. %LOCALAPPDATA%) are NOT
    /// expanded. Use the fully-resolved path.
    #[clap(long, env("KMS_ROLLING_LOG_DIR"), verbatim_doc_comment)]
    pub rolling_log_dir: Option<PathBuf>,

    /// The name of the rolling log file: <rolling_log_name>.YYYY-MM-DD.
    /// Defaults to `cosmian_kms` if not set.
    #[clap(long, env("KMS_ROLLING_LOG_NAME"), verbatim_doc_comment)]
    pub rolling_log_name: Option<String>,

    /// Enable metering in addition to tracing when telemetry is enabled
    #[clap(long, env("KMS_ENABLE_METERING"), default_value = "false")]
    pub enable_metering: bool,

    /// The name of the environment (development, test, production, etc.)
    /// This will be added to the telemetry data if telemetry is enabled
    #[clap(
        long,
        env("KMS_ENVIRONMENT"),
        default_value = "development",
        verbatim_doc_comment
    )]
    pub environment: Option<String>,

    /// Enable ANSI colors in the logs to stdout
    #[clap(
        long,
        env("KMS_ANSI_COLORS"),
        default_value = "false",
        verbatim_doc_comment
    )]
    pub ansi_colors: bool,
}
