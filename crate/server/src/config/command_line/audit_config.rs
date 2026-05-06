use std::path::PathBuf;

use clap::Args;
use serde::{Deserialize, Serialize};

/// Configuration for the file-based audit log sub-section.
#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AuditFileConfig {
    /// Path to the JSONL audit log file.
    ///
    /// When `--audit-enable` is set and this option is omitted, the file
    /// defaults to `<root-data-path>/audit.jsonl`.
    #[clap(long, env = "KMS_AUDIT_FILE_PATH", verbatim_doc_comment)]
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
    #[clap(long, env = "KMS_AUDIT_ENABLE", default_value = "false")]
    pub audit_enable: bool,

    #[clap(flatten)]
    pub file: AuditFileConfig,
}
