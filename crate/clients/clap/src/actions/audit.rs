//! `ckms audit` subcommands — read audit events either from a local JSONL file, or from a
//! `PostgreSQL` audit database, with no other KMS server connection required.
//!
//! These commands bypass the normal `ClientConfig::load()` bootstrap so they
//! can be used offline (e.g. on an isolated audit workstation that has the
//! audit file but no access to the KMS server).
//!
//! Subcommands
//! ===========
//! * `export` — reads events and writes them to stdout (JSON or CEF v27)
//! * `verify` — validates the SHA-256 hash chain; exits non-zero if broken
//!
//! Source selection
//! ================
//! Exactly one of `--path` (JSONL file) or `--postgres-url` (`PostgreSQL` audit database) must
//! be supplied. A file always holds exactly one hash chain; a `PostgreSQL` database holds one
//! independent chain per `instance_id` — `--instance-id` restricts processing to a single one,
//! otherwise every chain in the database is processed in turn. Chains are never concatenated:
//! each starts at `id = 0` with an all-zeros `prev_hash`, so mixing them would make `verify`
//! report a spurious break at every chain boundary.

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use cosmian_kms_client::reexport::cosmian_kms_access::audit::{
    AuditEvent, AuditResult, to_cef_line, verify_chain_link, verify_event,
};
use cosmian_kms_server_database::PgAuditReader;

use crate::error::result::KmsCliResult;

/// Commands for managing and inspecting the KMS audit log.
///
/// These commands read audit events directly from a file or a `PostgreSQL` database — no
/// running KMS server is required.
#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Export audit events to stdout (JSON lines or CEF v27 format).
    Export(ExportAuditAction),
    /// Verify the SHA-256 hash chain of the audit log.
    Verify(VerifyAuditAction),
}

impl AuditCommands {
    /// Dispatch to the matching subcommand.
    ///
    /// # Errors
    /// Returns an error if the audit source cannot be read or if I/O fails.
    pub async fn process(&self) -> KmsCliResult<()> {
        match self {
            Self::Export(action) => action.run().await,
            Self::Verify(action) => action.run().await,
        }
    }
}

/// Common source-selection arguments shared by `export` and `verify`.
#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("audit_source").required(true).multiple(false)))]
struct AuditSourceArgs {
    /// Path to the JSONL audit log file.
    #[clap(long, short = 'p', env = "KMS_AUDIT_FILE_PATH", group = "audit_source")]
    path: Option<PathBuf>,

    /// `PostgreSQL` URL of the audit database. Use a read-only role: these commands only ever
    /// `SELECT`, and granting more would undermine the append-only guarantee the server relies
    /// on.
    #[clap(long, env = "KMS_AUDIT_POSTGRES_URL", group = "audit_source")]
    postgres_url: Option<String>,

    /// Restrict to one instance's chain. Only meaningful with `--postgres-url`; when omitted
    /// every chain in the database is processed in turn, because each is verified
    /// independently.
    #[clap(long, env = "KMS_AUDIT_INSTANCE_ID", requires = "postgres_url")]
    instance_id: Option<String>,
}

/// One independent hash chain to verify or export.
///
/// A file holds exactly one; a `PostgreSQL` database holds one per `instance_id`. `label` is
/// `None` for the file backend (there is only ever one chain, so a per-chain label adds no
/// information) and `Some(instance_id)` for `PostgreSQL`.
struct Chain {
    label: Option<String>,
    events: Vec<AuditEvent>,
}

impl AuditSourceArgs {
    /// Loads every chain named by this source: a single chain for the file backend, or one
    /// chain per instance (all of them, or the single one requested via `--instance-id`) for the
    /// `PostgreSQL` backend.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, a line cannot be parsed, or the `PostgreSQL`
    /// database cannot be reached or queried.
    async fn load_chains(&self) -> KmsCliResult<Vec<Chain>> {
        if let Some(path) = &self.path {
            let events = read_file_events(path)?;
            return Ok(vec![Chain {
                label: None,
                events,
            }]);
        }

        let url = self.postgres_url.as_deref().ok_or_else(|| {
            crate::error::KmsCliError::InvalidRequest(
                "either --path or --postgres-url must be supplied".to_owned(),
            )
        })?;
        let reader = PgAuditReader::connect(url)
            .await
            .map_err(|e| crate::error::KmsCliError::InvalidRequest(e.to_string()))?;

        let instances = match &self.instance_id {
            Some(id) => vec![id.clone()],
            None => reader
                .list_instances()
                .await
                .map_err(|e| crate::error::KmsCliError::InvalidRequest(e.to_string()))?,
        };

        let mut chains = Vec::with_capacity(instances.len());
        for instance in instances {
            let events = reader
                .events_for_instance(&instance)
                .await
                .map_err(|e| crate::error::KmsCliError::InvalidRequest(e.to_string()))?;
            chains.push(Chain {
                label: Some(instance),
                events,
            });
        }
        Ok(chains)
    }
}

/// Reads and parses every event from a JSONL audit file.
fn read_file_events(path: &PathBuf) -> KmsCliResult<Vec<AuditEvent>> {
    let file = std::fs::File::open(path).map_err(crate::error::KmsCliError::IoError)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
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
        events.push(event);
    }
    Ok(events)
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

/// Export audit events to stdout.
///
/// Each event is printed on its own line.  Use `--since` to filter by time and
/// `--format` to choose between JSON (default) and CEF v27 output.
///
/// # Examples
///
/// ```sh
/// # Print all events as JSON, from a file
/// ckms audit export --path /data/kms/audit.jsonl
///
/// # Print events since 2024-01-01 in CEF format, from PostgreSQL
/// ckms audit export --postgres-url "$KMS_AUDIT_POSTGRES_URL" \
///     --since 2024-01-01T00:00:00Z --format cef
/// ```
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportAuditAction {
    #[clap(flatten)]
    source: AuditSourceArgs,

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
    /// Runs the export, writing output to `stdout`.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read.
    pub async fn run(&self) -> KmsCliResult<()> {
        self.run_with_writer(&mut std::io::stdout().lock()).await
    }

    /// Runs the export, writing output to the provided writer.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read or a line cannot be parsed.
    pub(crate) async fn run_with_writer<W: Write>(&self, out: &mut W) -> KmsCliResult<()> {
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

        let chains = self.source.load_chains().await?;
        for chain in chains {
            for event in chain.events {
                if let Some(ts) = since {
                    if event.timestamp < ts {
                        continue;
                    }
                }
                let output_line = match self.format {
                    ExportFormat::Json => serde_json::to_string(&event).map_err(|e| {
                        crate::error::KmsCliError::InvalidRequest(format!(
                            "cannot serialise audit event: {e}"
                        ))
                    })?,
                    ExportFormat::Cef => to_cef_line(&event, &self.kms_version),
                };
                writeln!(out, "{output_line}").map_err(crate::error::KmsCliError::IoError)?;
            }
        }

        Ok(())
    }
}

/// Verify the SHA-256 hash chain of the audit log.
///
/// Checks that:
/// 1. Each event's `row_hash` matches a freshly computed hash of its fields.
/// 2. Each event's `prev_hash` matches the `row_hash` of the previous event
///    (or is all-zeros for the first event).
///
/// Exits with code **0** when every chain is intact, or **1** when a broken
/// link is detected (the ID of the first failing event is printed).
///
/// # Example
///
/// ```sh
/// ckms audit verify --path /data/kms/audit.jsonl
/// ckms audit verify --postgres-url "$KMS_AUDIT_POSTGRES_URL"
/// ```
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct VerifyAuditAction {
    #[clap(flatten)]
    source: AuditSourceArgs,

    /// Print a summary line for every event even when the chain is valid.
    #[clap(long, default_value = "false")]
    pub verbose: bool,
    // TODO: add a `--prev-hash` option (hex string) so that rotated files
    //       can be verified by supplying the row_hash of the last event in
    //       the preceding file segment.
}

impl VerifyAuditAction {
    /// Runs the verification, printing one summary line per chain to `stdout`.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read, or if a broken hash-chain link is
    /// detected (exit code 1).
    pub async fn run(&self) -> KmsCliResult<()> {
        self.run_with_writer(&mut std::io::stdout().lock()).await
    }

    /// Runs the verification, writing one summary line per chain to the provided writer.
    ///
    /// Returns `Err` containing the human-readable diagnosis on the first broken
    /// link ("TAMPERED: …" or "CHAIN BROKEN: …"), allowing callers to assert on
    /// the exact error message format.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read, or the chain is broken.
    pub(crate) async fn run_with_writer<W: Write>(&self, out: &mut W) -> KmsCliResult<()> {
        let chains = self.source.load_chains().await?;

        for chain in chains {
            let mut prev: Option<AuditEvent> = None;
            let mut total: u64 = 0;

            for event in chain.events {
                if !verify_event(&event) {
                    return Err(crate::error::KmsCliError::InvalidRequest(format!(
                        "TAMPERED: event id={} has an invalid row_hash{}",
                        event.id,
                        chain_suffix(&chain.label)
                    )));
                }

                if !verify_chain_link(&event, prev.as_ref()) {
                    return Err(crate::error::KmsCliError::InvalidRequest(format!(
                        "CHAIN BROKEN: event id={} prev_hash does not match the row_hash of \
                         event id={}{}",
                        event.id,
                        prev.as_ref().map_or(-1, |p| p.id),
                        chain_suffix(&chain.label)
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
                out,
                "Audit chain OK: {total} event{} verified{}",
                if total == 1 { "" } else { "s" },
                chain_suffix(&chain.label)
            )
            .map_err(crate::error::KmsCliError::IoError)?;
        }

        Ok(())
    }
}

/// Renders `" (instance_id=…)"` for a labelled (`PostgreSQL`) chain, or an empty string for the
/// unlabelled file chain.
fn chain_suffix(label: &Option<String>) -> String {
    label
        .as_ref()
        .map_or_else(String::new, |l| format!(" (instance_id={l})"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::{io::Write as _, path::PathBuf};

    use cosmian_kms_client::reexport::cosmian_kms_access::audit::{
        AuditEvent, AuditResult, compute_row_hash,
    };
    use time::OffsetDateTime;

    use super::{AuditSourceArgs, ExportAuditAction, ExportFormat, VerifyAuditAction};

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
            source: AuditSourceArgs {
                path: Some(path),
                postgres_url: None,
                instance_id: None,
            },
            verbose: false,
        }
    }

    fn export_action(path: PathBuf, format: ExportFormat) -> ExportAuditAction {
        ExportAuditAction {
            source: AuditSourceArgs {
                path: Some(path),
                postgres_url: None,
                instance_id: None,
            },
            since: None,
            format,
            kms_version: "test".to_owned(),
        }
    }

    // ── VerifyAuditAction ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_ok_reports_n_events_verified() {
        let path = temp_path("verify_ok");
        make_chain(3, &path);
        let mut out = Vec::new();
        verify_action(path).run_with_writer(&mut out).await.unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("Audit chain OK: 3 events verified"), "{msg}");
    }

    #[tokio::test]
    async fn verify_empty_file_is_ok() {
        let path = temp_path("verify_empty");
        std::fs::File::create(&path).unwrap();
        let mut out = Vec::new();
        verify_action(path).run_with_writer(&mut out).await.unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.contains("Audit chain OK: 0 events verified"), "{msg}");
    }

    #[tokio::test]
    async fn verify_detects_tampered_row_hash() {
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
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TAMPERED") && msg.contains("event id=1"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn verify_detects_broken_chain_link() {
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
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("CHAIN BROKEN") && msg.contains("event id=2"),
            "{msg}"
        );
    }

    // ── ExportAuditAction ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn export_json_outputs_parseable_lines() {
        let path = temp_path("export_json");
        make_chain(3, &path);
        let mut out = Vec::new();
        export_action(path, ExportFormat::Json)
            .run_with_writer(&mut out)
            .await
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            drop(serde_json::from_str::<AuditEvent>(line).unwrap());
        }
    }

    #[tokio::test]
    async fn export_cef_lines_have_cef_prefix() {
        let path = temp_path("export_cef");
        make_chain(3, &path);
        let mut out = Vec::new();
        export_action(path, ExportFormat::Cef)
            .run_with_writer(&mut out)
            .await
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        for line in text.lines() {
            assert!(line.starts_with("CEF:0|"), "{line}");
        }
    }

    #[tokio::test]
    async fn export_since_filter_drops_earlier_events() {
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
            source: AuditSourceArgs {
                path: Some(path),
                postgres_url: None,
                instance_id: None,
            },
            since: Some(since_str),
            format: ExportFormat::Json,
            kms_version: "test".to_owned(),
        };
        let mut out = Vec::new();
        action.run_with_writer(&mut out).await.unwrap();
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
