//! `ckms audit` subcommands — work directly on the JSONL audit file, no KMS
//! server connection required.
//!
//! These commands bypass the normal `ClientConfig::load()` bootstrap so they
//! can be used offline (e.g. on an isolated audit workstation that has the
//! audit file but no access to the KMS server).
//!
//! Subcommands
//! ===========
//! * `export` — reads the file and writes events to stdout (JSON or CEF v27)
//! * `verify` — validates the SHA-256 hash chain; exits non-zero if broken

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand, ValueEnum};
use cosmian_kms_client::reexport::cosmian_kms_access::audit::{
    AuditEvent, AuditResult, sha256_file, to_cef_line, verify_chain_link, verify_event,
};

use crate::error::result::KmsCliResult;

/// Commands for managing and inspecting the KMS audit log.
///
/// These commands read the audit file directly — no running KMS server is
/// required.
#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Export audit events to stdout (JSON lines or CEF v27 format).
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

/// Output format for `ckms audit export`.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ExportFormat {
    /// Output each event as a JSON object (default — same as the stored format).
    #[default]
    Json,
    /// Output each event as a CEF v27 syslog line.
    Cef,
}

/// Export audit events from the JSONL log file to stdout.
///
/// Each event is printed on its own line.  Use `--since` to filter by time and
/// `--format` to choose between JSON (default) and CEF v27 output.
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
    /// Run the export, writing output to `stdout`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened or read.
    pub fn run(&self) -> KmsCliResult<()> {
        self.run_with_writer(&mut std::io::stdout().lock())
    }

    /// Run the export, writing output to the provided writer.
    ///
    /// For stdout call `run_with_writer(&mut std::io::stdout().lock())`.
    /// For tests pass `&mut Vec::new()` and inspect the captured bytes.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened, read, or a line cannot be parsed.
    pub(crate) fn run_with_writer<W: Write>(&self, out: &mut W) -> KmsCliResult<()> {
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

        let file = std::fs::File::open(&self.path).map_err(crate::error::KmsCliError::IoError)?;
        let reader = BufReader::new(file);

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(crate::error::KmsCliError::IoError)?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEvent = serde_json::from_str(&line).map_err(|e| {
                crate::error::KmsCliError::InvalidRequest(format!(
                    "line {}: malformed audit event: {e}",
                    line_no + 1
                ))
            })?;

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

/// Verify the SHA-256 hash chain of the audit log file.
///
/// Checks that:
/// 1. Each event's `row_hash` matches a freshly computed hash of its fields.
/// 2. Each event's `prev_hash` matches the `row_hash` of the previous event
///    (or is all-zeros for the first event).
/// 3. Every `audit:reanchor` event's sealed evidence file still exists next to the
///    log and its SHA-256 still matches the digest recorded in the event.
///
/// `--path` may be a single file or a directory. A directory is scanned for every
/// `*.jsonl` file, each verified as its own **independent** chain.
///
/// Exits with code **0** when every chain is intact, or **1** when a broken
/// link, tampered event, or altered/missing sealed-evidence file is detected
/// (the first failure is printed).
///
/// # Example
///
/// ```sh
/// ckms audit verify --path /data/kms/audit.jsonl
/// ckms audit verify --path /data/kms/audit-logs/
/// ```
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct VerifyAuditAction {
    /// Path to a JSONL audit log file, or a directory containing one or more.
    #[clap(long, short = 'p', env = "KMS_AUDIT_FILE_PATH")]
    pub path: PathBuf,

    /// Print a summary line for every event even when the chain is valid.
    #[clap(long, default_value = "false")]
    pub verbose: bool,
    // TODO: add a `--prev-hash` option (hex string) so that rotated files
    //       can be verified by supplying the row_hash of the last event in
    //       the preceding file segment.
}

impl VerifyAuditAction {
    /// Run the verification, printing the summary to `stdout`.
    ///
    /// # Errors
    /// Returns an error if the path cannot be opened or read, if a broken
    /// hash-chain link is detected, or if sealed reanchor evidence is
    /// missing/altered (exit code 1).
    pub fn run(&self) -> KmsCliResult<()> {
        self.run_with_writer(&mut std::io::stdout().lock())
    }

    /// Run the verification, writing the summary to the provided writer.
    ///
    /// When `path` is a directory, every `*.jsonl` file in it is verified as its own
    /// independent chain. Returns `Err` containing the human-readable diagnosis on the
    /// first broken link, tampered event, or altered/missing sealed-evidence file.
    ///
    /// # Errors
    /// Returns an error if the path cannot be opened, read, or a chain/evidence check fails.
    pub(crate) fn run_with_writer<W: Write>(&self, out: &mut W) -> KmsCliResult<()> {
        if self.path.is_dir() {
            let mut files: Vec<PathBuf> = std::fs::read_dir(&self.path)
                .map_err(crate::error::KmsCliError::IoError)?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|p| {
                    p.extension().and_then(|e| e.to_str()) == Some("jsonl")
                        && !is_sealed_audit_evidence_file(p)
                })
                .collect();
            files.sort();

            if files.is_empty() {
                return Err(crate::error::KmsCliError::InvalidRequest(format!(
                    "no *.jsonl audit files found in {}",
                    self.path.display()
                )));
            }

            for file in &files {
                writeln!(out, "== {} ==", file.display())
                    .map_err(crate::error::KmsCliError::IoError)?;
                self.verify_one_file(file, out)?;
            }
            Ok(())
        } else {
            self.verify_one_file(&self.path, out)
        }
    }

    /// Verifies a single JSONL file as one independent hash chain.
    fn verify_one_file<W: Write>(&self, path: &Path, out: &mut W) -> KmsCliResult<()> {
        let file = std::fs::File::open(path).map_err(crate::error::KmsCliError::IoError)?;

        let reader = BufReader::new(file);
        let mut prev: Option<AuditEvent> = None;
        let mut total: u64 = 0;

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(crate::error::KmsCliError::IoError)?;
            if line.trim().is_empty() {
                continue;
            }

            let event: AuditEvent = serde_json::from_str(&line).map_err(|e| {
                crate::error::KmsCliError::InvalidRequest(format!(
                    "{}: line {}: malformed audit event: {e}",
                    path.display(),
                    line_no + 1
                ))
            })?;

            if !verify_event(&event) {
                return Err(crate::error::KmsCliError::InvalidRequest(format!(
                    "TAMPERED: {} event id={} (line {}) has an invalid row_hash",
                    path.display(),
                    event.id,
                    line_no + 1
                )));
            }

            if !verify_chain_link(&event, prev.as_ref()) {
                return Err(crate::error::KmsCliError::InvalidRequest(format!(
                    "CHAIN BROKEN: {} event id={} (line {}) prev_hash does not match \
                     the row_hash of event id={}",
                    path.display(),
                    event.id,
                    line_no + 1,
                    prev.as_ref().map_or(-1, |p| p.id)
                )));
            }

            if event.operation == "audit:reanchor" {
                Self::verify_reanchor_evidence(path, &event)?;
                eprintln!(
                    "WARNING: {} id={} is a reanchor record — the chain was reset here \
                     after sealing corrupted evidence aside; see its `details` field",
                    path.display(),
                    event.id
                );
            } else if event.operation == "audit:torn-write-recovered" && self.verbose {
                eprintln!(
                    "INFO: {} id={} recovered from a torn (interrupted) write",
                    path.display(),
                    event.id
                );
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
            out,
            "{}: chain OK: {total} event{} verified",
            path.display(),
            if total == 1 { "" } else { "s" }
        )
        .map_err(crate::error::KmsCliError::IoError)
    }

    /// Confirms a reanchor event's sealed-evidence file still exists next to `path` and
    /// its SHA-256 still matches the digest recorded in the event's `details` field —
    /// this is what makes deleting or altering sealed evidence after the fact detectable.
    fn verify_reanchor_evidence(path: &Path, event: &AuditEvent) -> KmsCliResult<()> {
        let details = event.details.as_deref().ok_or_else(|| {
            crate::error::KmsCliError::InvalidRequest(format!(
                "{}: reanchor event id={} is missing its `details` payload",
                path.display(),
                event.id
            ))
        })?;
        let parsed: serde_json::Value = serde_json::from_str(details).map_err(|e| {
            crate::error::KmsCliError::InvalidRequest(format!(
                "{}: reanchor event id={}: malformed details JSON: {e}",
                path.display(),
                event.id
            ))
        })?;
        let malformed = || {
            crate::error::KmsCliError::InvalidRequest(format!(
                "{}: reanchor event id={} details is missing `sealed_file` or `sha256`",
                path.display(),
                event.id
            ))
        };
        let sealed_file = parsed
            .get("sealed_file")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(malformed)?;
        let expected_sha256 = parsed
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(malformed)?;

        let sealed_path = path.parent().map_or_else(
            || PathBuf::from(sealed_file),
            |parent| parent.join(sealed_file),
        );

        if !sealed_path.exists() {
            return Err(crate::error::KmsCliError::InvalidRequest(format!(
                "MISSING EVIDENCE: {}: reanchor event id={} references sealed file {} \
                 which no longer exists",
                path.display(),
                event.id,
                sealed_path.display()
            )));
        }

        let (actual_sha256, _size) =
            sha256_file(&sealed_path).map_err(crate::error::KmsCliError::IoError)?;
        if actual_sha256 != expected_sha256 {
            return Err(crate::error::KmsCliError::InvalidRequest(format!(
                "TAMPERED EVIDENCE: {}: reanchor event id={}: sealed file {} SHA-256 \
                 mismatch (expected {expected_sha256}, got {actual_sha256})",
                path.display(),
                event.id,
                sealed_path.display()
            )));
        }

        Ok(())
    }
}

/// Returns whether `path` follows the seal-and-roll evidence naming convention.
///
/// Sealed files are intentionally not required to form valid chains themselves: their
/// corruption is the reason they were preserved. `ckms audit verify` validates their
/// integrity through the live log's `audit:reanchor` SHA-256 reference instead.
fn is_sealed_audit_evidence_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".corrupt."))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::{io::Write as _, path::PathBuf};

    use cosmian_kms_client::reexport::cosmian_kms_access::audit::{
        AuditEvent, AuditResult, compute_row_hash,
    };
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;

    use super::{ExportAuditAction, ExportFormat, VerifyAuditAction};

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kms_cli_audit_test_{}_{label}.jsonl",
            std::process::id()
        ))
    }

    /// Build a valid N-event hash chain, writing to `path` and returning the events.
    fn make_chain(n: u64, path: &PathBuf) -> Vec<AuditEvent> {
        let mut events: Vec<AuditEvent> = Vec::new();
        let mut file = std::fs::File::create(path).unwrap();

        for i in 0..n {
            let prev_hash = events
                .last()
                .map_or([0_u8; 32], |e: &AuditEvent| e.row_hash);
            let mut event = AuditEvent {
                id: i64::try_from(i).unwrap(),
                timestamp: OffsetDateTime::now_utc(),
                operation: format!("Op{i}"),
                user: "test-user".to_owned(),
                object_uid: Some(format!("uid-{i}")),
                algorithm: Some("AES-256-GCM".to_owned()),
                client_ip: Some("127.0.0.1".to_owned()),
                result: AuditResult::Success,
                duration_ms: 1,
                request_id: None,
                details: None,
                prev_hash,
                row_hash: [0_u8; 32],
            };
            event.row_hash = compute_row_hash(&event);
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
            events.push(event);
        }
        events
    }

    fn verify_action(path: PathBuf) -> VerifyAuditAction {
        VerifyAuditAction {
            path,
            verbose: false,
        }
    }

    fn export_action(path: PathBuf, format: ExportFormat) -> ExportAuditAction {
        ExportAuditAction {
            path,
            since: None,
            format,
            kms_version: "test".to_owned(),
        }
    }

    // ── VerifyAuditAction ──────────────────────────────────────────────────────

    #[test]
    fn verify_ok_reports_n_events_verified() {
        let path = temp_path("verify_ok");
        make_chain(3, &path);
        let mut out = Vec::new();
        verify_action(path).run_with_writer(&mut out).unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("chain OK: 3 events verified"), "{msg}");
    }

    #[test]
    fn verify_empty_file_is_ok() {
        let path = temp_path("verify_empty");
        std::fs::File::create(&path).unwrap();
        let mut out = Vec::new();
        verify_action(path).run_with_writer(&mut out).unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("chain OK: 0 events verified"), "{msg}");
    }

    #[test]
    fn verify_detects_tampered_row_hash() {
        let path = temp_path("verify_tampered");
        let mut events = make_chain(3, &path);

        // Corrupt event id=1
        events[1].row_hash[0] ^= 0xff;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        for ev in &events {
            writeln!(file, "{}", serde_json::to_string(ev).unwrap()).unwrap();
        }

        let err = verify_action(path)
            .run_with_writer(&mut Vec::new())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TAMPERED") && msg.contains("event id=1"),
            "{msg}"
        );
    }

    #[test]
    fn verify_detects_broken_chain_link() {
        let path = temp_path("verify_chain");
        let mut events = make_chain(3, &path);

        // Break the link: corrupt prev_hash of event id=2 (chain link from id=1)
        events[2].prev_hash[0] ^= 0xff;
        // Recompute row_hash so the TAMPERED check passes; only chain check fails
        events[2].row_hash = compute_row_hash(&events[2]);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        for ev in &events {
            writeln!(file, "{}", serde_json::to_string(ev).unwrap()).unwrap();
        }

        let err = verify_action(path)
            .run_with_writer(&mut Vec::new())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("CHAIN BROKEN") && msg.contains("event id=2"),
            "{msg}"
        );
    }

    // ── Directory mode ───────────────────────────────────────────────────────

    #[test]
    fn verify_directory_checks_each_jsonl_as_independent_chain() {
        let dir =
            std::env::temp_dir().join(format!("kms_cli_audit_test_{}_dir", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        make_chain(2, &dir.join("a.jsonl"));
        make_chain(3, &dir.join("b.jsonl"));
        std::fs::write(dir.join("not_jsonl.txt"), b"ignored").unwrap();

        let mut out = Vec::new();
        verify_action(dir.clone())
            .run_with_writer(&mut out)
            .unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("a.jsonl"), "{msg}");
        assert!(msg.contains("b.jsonl"), "{msg}");
        assert!(msg.contains("chain OK: 2 events verified"), "{msg}");
        assert!(msg.contains("chain OK: 3 events verified"), "{msg}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_directory_checks_reanchor_evidence_without_verifying_it_as_a_chain() {
        let dir = std::env::temp_dir().join(format!(
            "kms_cli_audit_test_{}_reanchor_dir",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let live_path = dir.join("audit.jsonl");
        std::fs::File::create(&live_path).unwrap();
        let sealed_path = append_reanchor(&live_path, b"intentionally malformed evidence", false);

        let mut out = Vec::new();
        verify_action(dir.clone())
            .run_with_writer(&mut out)
            .unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(
            msg.contains("audit.jsonl: chain OK: 1 event verified"),
            "{msg}"
        );
        assert!(
            !msg.contains(&sealed_path.display().to_string()),
            "sealed evidence must be digest-checked via its reanchor, not verified as a chain: {msg}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_directory_rejects_empty_directory() {
        let dir = std::env::temp_dir().join(format!(
            "kms_cli_audit_test_{}_empty_dir",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let err = verify_action(dir.clone())
            .run_with_writer(&mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().contains("no *.jsonl audit files found"));

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Reanchor sealed-evidence cross-check ─────────────────────────────────

    /// Appends a synthetic `audit:reanchor` row (as produced by `seal_and_roll`) to
    /// `path`'s chain, referencing a sealed evidence file. Writes the sealed file with
    /// `sealed_content` and records its true SHA-256/size in the reanchor's `details`
    /// unless `corrupt_digest` overrides the recorded SHA-256 with a wrong one.
    ///
    /// The sealed filename is derived from `path`'s own stem (not a fixed constant) so
    /// concurrently-running tests never race on the same file in the shared temp dir.
    fn append_reanchor(path: &PathBuf, sealed_content: &[u8], corrupt_digest: bool) -> PathBuf {
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let sealed_path =
            path.with_file_name(format!("{stem}.20260814T000000Z.deadbeef.corrupt.jsonl"));
        std::fs::write(&sealed_path, sealed_content).unwrap();

        let mut hasher = Sha256::new();
        std::io::copy(&mut std::io::Cursor::new(sealed_content), &mut hasher).unwrap();
        let real_sha256 = hex::encode(hasher.finalize());
        let recorded_sha256 = if corrupt_digest {
            "0".repeat(64)
        } else {
            real_sha256
        };

        let details = format!(
            "{{\"sealed_file\":\"{}\",\"sha256\":\"{recorded_sha256}\",\"size\":{},\
             \"claimed_last_id\":0,\"failure_offset\":0,\"reason\":\"unparseable\"}}",
            sealed_path.file_name().unwrap().to_string_lossy(),
            sealed_content.len()
        );

        let mut event = AuditEvent {
            id: 0,
            timestamp: OffsetDateTime::now_utc(),
            operation: "audit:reanchor".to_owned(),
            user: "server".to_owned(),
            object_uid: None,
            algorithm: None,
            client_ip: None,
            result: AuditResult::Success,
            duration_ms: 0,
            request_id: None,
            details: Some(details),
            prev_hash: [0_u8; 32],
            row_hash: [0_u8; 32],
        };
        event.row_hash = compute_row_hash(&event);

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        sealed_path
    }

    #[test]
    fn verify_accepts_reanchor_with_matching_sealed_evidence() {
        let path = temp_path("reanchor_ok");
        std::fs::File::create(&path).unwrap();
        let sealed_path = append_reanchor(&path, b"some sealed corrupted content", false);

        let mut out = Vec::new();
        verify_action(path.clone())
            .run_with_writer(&mut out)
            .unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("chain OK: 1 event verified"), "{msg}");

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&sealed_path).ok();
    }

    #[test]
    fn verify_rejects_reanchor_with_missing_sealed_file() {
        let path = temp_path("reanchor_missing");
        std::fs::File::create(&path).unwrap();
        let sealed_path = append_reanchor(&path, b"content", false);
        // Delete the sealed file right after creating the reanchor record.
        std::fs::remove_file(&sealed_path).unwrap();

        let err = verify_action(path.clone())
            .run_with_writer(&mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().contains("MISSING EVIDENCE"), "{err}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verify_rejects_reanchor_with_tampered_sealed_file_digest() {
        let path = temp_path("reanchor_tampered");
        std::fs::File::create(&path).unwrap();
        let sealed_path = append_reanchor(&path, b"original content", true);

        let err = verify_action(path.clone())
            .run_with_writer(&mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().contains("TAMPERED EVIDENCE"), "{err}");

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&sealed_path).ok();
    }

    // ── ExportAuditAction ──────────────────────────────────────────────────────

    #[test]
    fn export_json_outputs_parseable_lines() {
        let path = temp_path("export_json");
        make_chain(3, &path);
        let mut out = Vec::new();
        export_action(path, ExportFormat::Json)
            .run_with_writer(&mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            drop(serde_json::from_str::<AuditEvent>(line).unwrap());
        }
    }

    #[test]
    fn export_cef_lines_have_cef_prefix() {
        let path = temp_path("export_cef");
        make_chain(3, &path);
        let mut out = Vec::new();
        export_action(path, ExportFormat::Cef)
            .run_with_writer(&mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        for line in text.lines() {
            assert!(line.starts_with("CEF:0|"), "{line}");
        }
    }

    #[test]
    fn export_since_filter_drops_earlier_events() {
        let path = temp_path("export_since");
        // Build chain with a known timestamp split
        let before = OffsetDateTime::now_utc();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let cutoff = OffsetDateTime::now_utc();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let after = OffsetDateTime::now_utc();

        // Write 3 events: one before, one at cutoff, one after
        let mut file = std::fs::File::create(&path).unwrap();
        let timestamps = [before, cutoff, after];
        let mut prev_hash = [0_u8; 32];
        for (i, ts) in timestamps.iter().enumerate() {
            let mut ev = AuditEvent {
                id: i64::try_from(i).unwrap(),
                timestamp: *ts,
                operation: "Encrypt".to_owned(),
                user: "u".to_owned(),
                object_uid: None,
                algorithm: None,
                client_ip: None,
                result: AuditResult::Success,
                duration_ms: 1,
                request_id: None,
                details: None,
                prev_hash,
                row_hash: [0_u8; 32],
            };
            ev.row_hash = compute_row_hash(&ev);
            prev_hash = ev.row_hash;
            writeln!(file, "{}", serde_json::to_string(&ev).unwrap()).unwrap();
        }

        let since_str = cutoff
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let action = ExportAuditAction {
            path,
            since: Some(since_str),
            format: ExportFormat::Json,
            kms_version: "test".to_owned(),
        };
        let mut out = Vec::new();
        action.run_with_writer(&mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Events at cutoff and after should appear; event before cutoff should be dropped
        assert_eq!(
            lines.len(),
            2,
            "expected 2 lines (cutoff + after), got:\n{text}"
        );
        let ev0: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(ev0.id, 1, "first kept event should have id=1 (cutoff)");
    }
}
