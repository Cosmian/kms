use std::path::PathBuf;

use clap::{Args, ValueEnum};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Default capacity of the bounded in-memory channel between request threads and
/// the audit writer task.
///
/// 4 096 events × ~500 B/event ≈ 2 MiB peak.  This absorbs ~4 seconds of
/// sustained load at 1 000 req/s on `NVMe` storage (one `fsync` ≈ 1 ms).
pub(crate) const DEFAULT_AUDIT_CHANNEL_CAPACITY: usize = 4_096;

/// Configuration for the file-based audit log sub-section.
#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AuditFileConfig {
    /// Path to the JSONL audit log file.
    ///
    /// When `--audit-enable` is set and this option is omitted, the file
    /// defaults to `<root-data-path>/audit.jsonl`.
    #[clap(
        long = "audit-file-path",
        env = "KMS_AUDIT_FILE_PATH",
        verbatim_doc_comment
    )]
    #[serde(rename = "path")]
    pub audit_file_path: Option<PathBuf>,

    /// Stops all further writes once the audit file reaches this many bytes.
    ///
    /// The event that pushes the file to or past this size is still persisted; every event
    /// after that is dropped (subject to `--audit-failure-mode`) until the log is remediated
    /// and the KMS is restarted.
    ///
    /// Omitted (the default) means unlimited. Must be > 0 when set.
    #[clap(
        long = "audit-file-max-size-bytes",
        env = "KMS_AUDIT_FILE_MAX_SIZE_BYTES",
        verbatim_doc_comment
    )]
    #[serde(rename = "max_size_bytes")]
    pub audit_file_max_size_bytes: Option<u64>,
}

/// Configuration for the structured audit event pipeline.
///
/// Audit logging is **disabled by default**.  Enable it with `--audit-enable`
/// or by setting the environment variable `KMS_AUDIT_ENABLE=true`.
///
/// When enabled, every KMIP operation (including authentication failures) is
/// appended as a tamper-evident JSON line to the audit file, and each entry
/// carries a SHA-256 hash chain so the log can be verified offline with
/// `ckms audit verify --path <file>`.
///
/// Compliance: PCI-DSS Req. 10, HIPAA §164.312(b), NIST SP 800-66r2.
#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable the structured audit event pipeline.
    ///
    /// When disabled (the default) no audit file is created and no background
    /// writer task is spawned.  The value can also be toggled at config-file
    /// level (`[audit] enable = true`).
    #[clap(
        long = "audit-enable",
        env = "KMS_AUDIT_ENABLE",
        default_value = "false"
    )]
    #[serde(rename = "enabled")]
    pub audit_enable: bool,

    #[clap(flatten)]
    #[serde(rename = "file")]
    pub file: AuditFileConfig,

    /// Capacity of the bounded in-memory channel between request threads and the
    /// audit writer task.
    ///
    /// When the channel is full, incoming events are dropped (non-blocking) and
    /// an `error!` is logged.  Each event is ≈500 B, so the default (4 096 × 500 B
    /// ≈ 2 MiB) absorbs short bursts without blocking request threads.
    ///
    /// Must be ≥ 1.  Raise this value if you see `"AuditFileStore: channel full"`
    /// in the server log under sustained high load.
    #[clap(
        long = "audit-channel-capacity",
        env = "KMS_AUDIT_CHANNEL_CAPACITY",
        default_value_t = DEFAULT_AUDIT_CHANNEL_CAPACITY,
        verbatim_doc_comment
    )]
    #[serde(rename = "channel_capacity", default = "default_channel_capacity")]
    pub audit_channel_capacity: usize,

    /// Only set this if the KMS sits behind a reverse proxy or load balancer.
    ///
    /// When set, the audit middleware trusts the `X-Forwarded-For` header only if
    /// the direct TCP peer is one of the proxy addresses listed here, and records
    /// the header's value as `client_ip` instead. This must be scoped to your
    /// proxy's own address(es) — trusting it from any peer lets a remote attacker
    /// forge `client_ip` in the audit trail.
    ///
    /// Format: comma-separated IP addresses or CIDR blocks, e.g.
    /// `"10.0.0.0/8,172.16.0.0/12"`. Single IPs can be expressed as `/32` (IPv4)
    /// or `/128` (IPv6).
    #[clap(
        long = "audit-trusted-proxy-cidrs",
        env = "KMS_AUDIT_TRUSTED_PROXY_CIDRS",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    #[serde(rename = "trusted_proxy_cidrs", default)]
    pub audit_trusted_proxy_cidrs: Vec<IpNet>,

    /// What to do when an audit event cannot be queued (channel full or writer dead).
    ///
    /// `continue` (default): log the error, keep serving normally.
    /// `reject`: return HTTP 503 to the client. The KMIP operation has already
    /// executed at this point — this signals that its outcome was not recorded,
    /// it does not prevent the operation from completing.
    #[clap(
        long = "audit-failure-mode",
        env = "KMS_AUDIT_FAILURE_MODE",
        default_value = "continue",
        verbatim_doc_comment
    )]
    #[serde(rename = "failure_mode", default)]
    pub audit_failure_mode: AuditFailureMode,
}

/// Controls what the KMS does when an audit event cannot be queued.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AuditFailureMode {
    /// Log the error and keep serving — no service disruption (default).
    #[default]
    Continue,
    /// Return 503 to the client when the event could not be queued.
    Reject,
}

/// Serde default helper for `AuditConfig::audit_channel_capacity`.
const fn default_channel_capacity() -> usize {
    DEFAULT_AUDIT_CHANNEL_CAPACITY
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::AuditFileConfig;

    /// `max_size_bytes` must round-trip through TOML and only appear when set —
    /// `None` (the default, unlimited) is omitted like every other `Option` field
    /// in this config (see `ClapConfig`'s own serialization test for the pattern).
    #[test]
    fn max_size_bytes_appears_in_toml_only_when_set() {
        let unset = AuditFileConfig::default();
        let unset_toml = toml::to_string_pretty(&unset).expect("must serialize");
        assert!(
            !unset_toml.contains("max_size_bytes"),
            "unset max_size_bytes must be omitted, got:\n{unset_toml}"
        );

        let set = AuditFileConfig {
            audit_file_max_size_bytes: Some(1_073_741_824),
            ..AuditFileConfig::default()
        };
        let set_toml = toml::to_string_pretty(&set).expect("must serialize");
        assert!(
            set_toml.contains("max_size_bytes = 1073741824"),
            "set max_size_bytes must appear in TOML, got:\n{set_toml}"
        );

        let parsed: AuditFileConfig = toml::from_str(&set_toml).expect("must round-trip");
        assert_eq!(parsed.audit_file_max_size_bytes, Some(1_073_741_824));
    }
}
