use std::fmt;

use clap::Args;
use serde::{Deserialize, Serialize};

/// SMTP configuration for email notifications sent when key auto-rotation events occur.
///
/// In the TOML configuration file this maps to the `[notifications.smtp]` section:
///
/// ```toml
/// [notifications.smtp]
/// host     = "smtp.example.com"
/// port     = 587
/// username = "kms-alerts@example.com"
/// password = "s3cr3t"
/// from     = "kms-alerts@example.com"
/// to       = "ops@example.com,security@example.com"
/// ```
///
/// All fields are optional. Email notifications are silently disabled if `host` is not set.
#[derive(Clone, Default, Serialize, Deserialize, Args)]
#[serde(default)]
pub struct SmtpConfig {
    /// SMTP server hostname (e.g. smtp.example.com).
    /// If not set, email notifications are disabled.
    #[clap(long = "smtp-host", env = "KMS_SMTP_HOST")]
    pub host: Option<String>,

    /// SMTP server port (default: 587 for STARTTLS).
    #[clap(
        id = "smtp_port",
        long = "smtp-port",
        env = "KMS_SMTP_PORT",
        default_value = "587"
    )]
    pub port: u16,

    /// SMTP authentication username.
    #[clap(long = "smtp-username", env = "KMS_SMTP_USERNAME")]
    pub username: Option<String>,

    /// SMTP authentication password.
    #[clap(long = "smtp-password", env = "KMS_SMTP_PASSWORD")]
    pub password: Option<String>,

    /// Sender address for notification emails (e.g. kms-alerts@example.com).
    #[clap(long = "smtp-from", env = "KMS_SMTP_FROM")]
    pub from: Option<String>,

    /// Comma-separated list of recipient email addresses for notifications.
    #[clap(long = "smtp-to", env = "KMS_SMTP_TO")]
    pub to: Option<String>,
}

/// Custom `Debug` implementation that masks the SMTP password to prevent it from
/// appearing in server startup logs (`info!("KMS Server configuration: {server_params:#?}")`).
impl fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_deref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .field("to", &self.to)
            .finish()
    }
}
