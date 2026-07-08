use std::path::PathBuf;

use clap::Args;
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
}

/// Serde default helper for `AuditConfig::audit_channel_capacity`.
const fn default_channel_capacity() -> usize {
    DEFAULT_AUDIT_CHANNEL_CAPACITY
}
