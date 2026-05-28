use clap::Args;
use serde::{Deserialize, Serialize};

use super::smtp_config::SmtpConfig;

/// Strategy controlling when and how renewal-warning notifications are sent.
///
/// ## Supported strategies
///
/// | Strategy TOML value | Behavior |
/// |---------------------|-----------|
/// | `"time_before_renewal"` | **(default)** Send warning emails at each interval in `warn_before_renewal_days` before the key is due for renewal. |
/// | `"rotation_only"` | Skip pre-renewal warnings entirely; only send the post-rotation success/failure notification. |
/// | `"silent"` | Suppress all renewal-related notifications (pre-warnings and post-rotation). |
///
/// ## Default behavior (`"time_before_renewal"`)
///
/// With the default strategy the server sends warning emails:
/// - **30 days** before the scheduled renewal
/// - **7 days** before the scheduled renewal
/// - **1 day** before the scheduled renewal
/// - Once the renewal has executed: a **success** or **failure** notification
///
/// Each warning is sent **exactly once** per renewal cycle: the server stores
/// `rotate_last_warning_days` on the key so that the same threshold is never
/// re-sent during subsequent cron checks.
#[derive(Clone, Debug, Serialize, Deserialize, Args)]
#[serde(default)]
pub struct RenewalNotificationStrategy {
    /// Notification strategy.
    ///
    /// | Value | Behaviour |
    /// |-------|-----------|
    /// | `time_before_renewal` | Emit warning emails at each interval in `warn_before_renewal_days` |
    /// | `rotation_only` | Only send success/failure notification after rotation |
    /// | `silent` | Suppress all renewal-related notifications |
    #[clap(
        long = "renewal-notification-strategy",
        env = "KMS_RENEWAL_NOTIFICATION_STRATEGY",
        default_value = "time_before_renewal",
        value_parser(["time_before_renewal", "rotation_only", "silent"]),
        verbatim_doc_comment
    )]
    pub strategy: String,

    /// Days before scheduled renewal at which a warning email is sent.
    ///
    /// Only used when `strategy = "time_before_renewal"`.
    /// Values are sorted descending internally; duplicates are ignored.
    /// Default: `[30, 7, 1]` — 1 month, 1 week, and 1 day before renewal.
    #[clap(
        long = "warn-before-renewal-days",
        env = "KMS_WARN_BEFORE_RENEWAL_DAYS",
        value_delimiter = ',',
        default_values_t = [30_u32, 7, 1]
    )]
    pub warn_before_renewal_days: Vec<u32>,

    /// Send a notification after successful key renewal. Default: `true`.
    #[clap(
        long = "notify-on-renewal-success",
        env = "KMS_NOTIFY_ON_RENEWAL_SUCCESS",
        default_value = "true"
    )]
    pub notify_on_success: bool,

    /// Send a notification after a failed key renewal attempt. Default: `true`.
    #[clap(
        long = "notify-on-renewal-failure",
        env = "KMS_NOTIFY_ON_RENEWAL_FAILURE",
        default_value = "true"
    )]
    pub notify_on_failure: bool,
}

impl Default for RenewalNotificationStrategy {
    fn default() -> Self {
        Self {
            strategy: "time_before_renewal".to_owned(),
            warn_before_renewal_days: vec![30, 7, 1],
            notify_on_success: true,
            notify_on_failure: true,
        }
    }
}

impl RenewalNotificationStrategy {
    /// Returns `true` if pre-renewal warning emails should be sent.
    #[must_use]
    pub fn warnings_enabled(&self) -> bool {
        self.strategy == "time_before_renewal"
    }

    /// Returns `true` if all notifications (warnings and post-rotation) are suppressed.
    #[must_use]
    pub fn all_silent(&self) -> bool {
        self.strategy == "silent"
    }

    /// Returns the warning thresholds sorted in **descending** order (largest first).
    #[must_use]
    pub fn sorted_thresholds(&self) -> Vec<u32> {
        let mut v = self.warn_before_renewal_days.clone();
        v.sort_unstable_by(|a, b| b.cmp(a));
        v.dedup();
        v
    }
}

/// Top-level notification configuration.
///
/// Groups all outbound notification channels used by the KMS server.
/// Currently only SMTP email is supported.
///
/// ```toml
/// [notifications.smtp]
/// host = "smtp.example.com"
/// port = 587
/// from = "kms@example.com"
/// to   = "ops@example.com"
///
/// [notifications.renewal]
/// strategy = "time_before_renewal"
/// warn_before_renewal_days = [30, 7, 1]
/// notify_on_success = true
/// notify_on_failure = true
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize, Args)]
#[serde(default)]
pub struct NotificationsConfig {
    /// SMTP email notification settings.
    /// Email notifications are disabled when `smtp.host` is not set.
    #[clap(flatten)]
    pub smtp: SmtpConfig,

    /// Renewal notification strategy — controls when and how warning emails
    /// are dispatched before and after scheduled key renewals.
    #[clap(flatten)]
    pub renewal: RenewalNotificationStrategy,
}
