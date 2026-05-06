//! `ckms audit` subcommands — work directly on the JSONL audit file, no KMS
//! server connection required.
//!
//! These commands bypass the normal `ClientConfig::load()` bootstrap so they
//! can be used offline (e.g. on an isolated audit workstation that has the
//! audit file but no access to the KMS server).
//!
//! Subcommands
//! ===========
//! * `export` — reads the file and writes events to stdout (JSON or CEF v25)
//! * `verify` — validates the SHA-256 hash chain; exits non-zero if broken

use std::{
    io::{BufRead, BufReader, Write as _},
    path::PathBuf,
};

use clap::{Parser, Subcommand, ValueEnum};
use cosmian_kms_client::reexport::cosmian_kms_access::audit::{
    AuditEventFull, AuditResult, to_cef_line, verify_chain_link, verify_event,
};

use crate::error::result::KmsCliResult;

// ── Top-level enum ────────────────────────────────────────────────────────────

/// Commands for managing and inspecting the KMS audit log.
///
/// These commands read the audit file directly — no running KMS server is
/// required.
#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Export audit events to stdout (JSON lines or CEF v25 format).
    Export(ExportAuditAction),
    /// Verify the SHA-256 hash chain of the audit file.
    Verify(VerifyAuditAction),
}

impl AuditCommands {
    /// Dispatch to the matching subcommand.
    ///
    /// # Errors
    /// Returns an error if the audit file cannot be read or if I/O fails.
    pub fn process(&self) -> KmsCliResult<()> {
        match self {
            Self::Export(action) => action.run(),
            Self::Verify(action) => action.run(),
        }
    }
}

// ── Export ────────────────────────────────────────────────────────────────────

/// Output format for `ckms audit export`.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ExportFormat {
    /// Output each event as a JSON object (default — same as the stored format).
    #[default]
    Json,
    /// Output each event as a CEF v25 syslog line.
    Cef,
}

/// Export audit events from the JSONL log file to stdout.
///
/// Each event is printed on its own line.  Use `--since` to filter by time and
/// `--format` to choose between JSON (default) and CEF v25 output.
///
/// # Examples
///
/// ```sh
/// # Print all events as JSON
/// ckms audit export --path /data/kms/audit.jsonl
///
/// # Print events since 2024-01-01 in CEF format
/// ckms audit export --path /data/kms/audit.jsonl \
///     --since 2024-01-01T00:00:00Z --format cef
/// ```
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportAuditAction {
    /// Path to the JSONL audit log file.
    #[clap(long, short = 'p', env = "KMS_AUDIT_FILE_PATH")]
    pub path: PathBuf,

    /// Only export events at or after this RFC 3339 timestamp
    /// (e.g. `2024-01-15T00:00:00Z`).
    #[clap(long, env = "KMS_AUDIT_SINCE")]
    pub since: Option<String>,

    /// Output format: `json` (default) or `cef`.
    #[clap(long, env = "KMS_AUDIT_FORMAT", default_value = "json")]
    pub format: ExportFormat,

    /// KMS version string to embed in CEF headers (e.g. "5.0.0").
    /// Defaults to the current binary version.
    #[clap(long, default_value = env!("CARGO_PKG_VERSION"))]
    pub kms_version: String,
}

impl ExportAuditAction {
    /// Run the export.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened or read.
    pub fn run(&self) -> KmsCliResult<()> {
        let since = self
            .since
            .as_deref()
            .map(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                    .map_err(|e| {
                        crate::error::KmsCliError::InvalidRequest(format!(
                            "--since must be an RFC 3339 timestamp: {e}"
                        ))
                    })
            })
            .transpose()?;

        let file =
            std::fs::File::open(&self.path).map_err(crate::error::KmsCliError::IoError)?;

        let reader = BufReader::new(file);
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(crate::error::KmsCliError::IoError)?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEventFull = serde_json::from_str(&line).map_err(|e| {
                crate::error::KmsCliError::InvalidRequest(format!(
                    "line {}: malformed audit event: {e}",
                    line_no + 1
                ))
            })?;

            // Apply --since filter
            if let Some(ts) = since {
                if event.timestamp < ts {
                    continue;
                }
            }

            let output_line = match self.format {
                ExportFormat::Json => line,
                ExportFormat::Cef => to_cef_line(&event, &self.kms_version),
            };

            writeln!(out, "{output_line}").map_err(crate::error::KmsCliError::IoError)?;
        }

        Ok(())
    }
}

// ── Verify ────────────────────────────────────────────────────────────────────

/// Verify the SHA-256 hash chain of the audit log file.
///
/// Checks that:
/// 1. Each event's `row_hash` matches a freshly computed hash of its fields.
/// 2. Each event's `prev_hash` matches the `row_hash` of the previous event
///    (or is all-zeros for the first event).
///
/// Exits with code **0** when the chain is intact, or **1** when a broken
/// link is detected (the ID of the first failing event is printed).
///
/// # Example
///
/// ```sh
/// ckms audit verify --path /data/kms/audit.jsonl
/// ```
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct VerifyAuditAction {
    /// Path to the JSONL audit log file.
    #[clap(long, short = 'p', env = "KMS_AUDIT_FILE_PATH")]
    pub path: PathBuf,

    /// Print a summary line for every event even when the chain is valid.
    #[clap(long, default_value = "false")]
    pub verbose: bool,
}

impl VerifyAuditAction {
    /// Run the verification.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened or read, or if a broken
    /// hash-chain link is detected (exit code 1).
    pub fn run(&self) -> KmsCliResult<()> {
        let file =
            std::fs::File::open(&self.path).map_err(crate::error::KmsCliError::IoError)?;

        let reader = BufReader::new(file);
        let mut prev: Option<AuditEventFull> = None;
        let mut total: u64 = 0;

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(crate::error::KmsCliError::IoError)?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEventFull = serde_json::from_str(&line).map_err(|e| {
                crate::error::KmsCliError::InvalidRequest(format!(
                    "line {}: malformed audit event: {e}",
                    line_no + 1
                ))
            })?;

            // 1. Verify the row's own hash
            if !verify_event(&event) {
                return Err(crate::error::KmsCliError::InvalidRequest(format!(
                    "TAMPERED: event id={} (line {}) has an invalid row_hash",
                    event.id,
                    line_no + 1
                )));
            }

            // 2. Verify the chain link from the previous event
            if !verify_chain_link(&event, prev.as_ref()) {
                return Err(crate::error::KmsCliError::InvalidRequest(format!(
                    "CHAIN BROKEN: event id={} (line {}) prev_hash does not match \
                     the row_hash of event id={}",
                    event.id,
                    line_no + 1,
                    prev.as_ref().map_or(-1, |p| p.id)
                )));
            }

            if self.verbose {
                let status = match &event.result {
                    AuditResult::Success => "ok",
                    AuditResult::Failure(_) => "fail",
                };
                eprintln!(
                    "id={:>6}  {}  {}  {}  chain=ok",
                    event.id,
                    event
                        .timestamp
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    event.operation,
                    status
                );
            }

            total += 1;
            prev = Some(event);
        }

        writeln!(
            std::io::stdout().lock(),
            "Audit chain OK: {total} event{} verified",
            if total == 1 { "" } else { "s" }
        )
        .map_err(crate::error::KmsCliError::IoError)
    }
}
