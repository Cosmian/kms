use std::path::PathBuf;

use clap::Args;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::workspace::WorkspaceConfig;
use crate::{
    config::params::{AuditBackendParams, AuditParams},
    kms_bail,
    result::KResult,
};

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

/// Configuration for the `PostgreSQL` audit log sub-section.
#[derive(Debug, Default, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AuditPostgresConfig {
    /// `PostgreSQL` connection URL for the audit database.
    ///
    /// When set, audit events are written to this `PostgreSQL` database instead of the JSONL
    /// file. This database MUST be a different database than the main object-storage database
    /// (`--database-url`) — the server refuses to start otherwise, since sharing one database
    /// would let the KMS's own object-store role bypass the audit database's append-only grants.
    #[clap(
        long = "audit-postgres-url",
        env = "KMS_AUDIT_POSTGRES_URL",
        verbatim_doc_comment
    )]
    #[serde(rename = "url")]
    pub audit_postgres_url: Option<String>,

    /// Identifies this KMS instance's audit hash chain when using the `PostgreSQL` backend.
    ///
    /// Must be STABLE across restarts and UNIQUE per KMS instance sharing the same audit
    /// database — two instances sharing an `instance_id` collide on their first concurrent
    /// write (`SQLSTATE` 23505) and the second one refuses to continue. Defaults to the machine
    /// hostname. Kubernetes deployments should set this explicitly (e.g. from the `StatefulSet`
    /// ordinal or the downward API) rather than rely on an ephemeral pod hostname.
    #[clap(
        long = "audit-instance-id",
        env = "KMS_AUDIT_INSTANCE_ID",
        verbatim_doc_comment
    )]
    #[serde(rename = "instance_id")]
    pub audit_instance_id: Option<String>,
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

    #[clap(flatten)]
    #[serde(rename = "postgres")]
    pub postgres: AuditPostgresConfig,

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
}

/// Serde default helper for `AuditConfig::audit_channel_capacity`.
const fn default_channel_capacity() -> usize {
    DEFAULT_AUDIT_CHANNEL_CAPACITY
}

impl AuditConfig {
    /// Resolves the CLI/TOML audit configuration into [`AuditParams`].
    ///
    /// Backend selection is config-time only: `[audit.postgres].url` set → `PostgreSQL`;
    /// otherwise → the JSONL file (path defaulting to `<root-data-path>/audit.jsonl`). There is
    /// no runtime fallback between the two — see the module-level ADR for why.
    ///
    /// # Errors
    /// Returns an error if audit logging is enabled with a `PostgreSQL` URL that:
    /// - does not start with `postgresql://` or `postgres://`,
    /// - resolves to the same host/port/database as `main_db_url` (the KMS's own
    ///   object-storage database — sharing one database would let the KMS bypass the audit
    ///   database's append-only grants using its object-store role),
    /// - or if the resolved `--audit-instance-id` is empty or exceeds 128 characters.
    pub(crate) fn init(
        &self,
        workspace: &WorkspaceConfig,
        main_db_url: Option<&str>,
    ) -> KResult<Option<AuditParams>> {
        if !self.audit_enable {
            return Ok(None);
        }

        let backend = if let Some(url) = self.postgres.audit_postgres_url.as_deref() {
            if !url.starts_with("postgresql://") && !url.starts_with("postgres://") {
                kms_bail!("PostgreSQL audit URL must start with 'postgresql://' or 'postgres://'");
            }
            if main_db_url.is_some_and(|main_url| {
                normalized_pg_authority(url) == normalized_pg_authority(main_url)
            }) {
                kms_bail!(
                    "The audit database (--audit-postgres-url) must be a different database \
                     than the main object-storage database (--database-url)."
                );
            }

            let instance_id = self
                .postgres
                .audit_instance_id
                .clone()
                .unwrap_or_else(default_instance_id);
            if instance_id.is_empty() || instance_id.len() > 128 {
                kms_bail!(
                    "--audit-instance-id must be non-empty and at most 128 characters, got {} \
                     characters",
                    instance_id.len()
                );
            }

            AuditBackendParams::Postgres {
                url: url.to_owned(),
                instance_id,
            }
        } else {
            let path = self
                .file
                .audit_file_path
                .clone()
                .unwrap_or_else(|| workspace.root_data_path.join("audit.jsonl"));
            AuditBackendParams::File { path }
        };

        Ok(Some(AuditParams {
            backend,
            channel_capacity: self.audit_channel_capacity,
            trusted_proxy_cidrs: self.audit_trusted_proxy_cidrs.clone(),
        }))
    }
}

/// Best-effort default so a bare `--audit-enable --audit-postgres-url=…` works out of the box
/// for a single-instance deployment. Kubernetes deployments should still set
/// `--audit-instance-id` explicitly — see the field doc comment.
fn default_instance_id() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-instance".to_owned())
}

/// Extracts `host:port,...\/dbname` (ignoring credentials and query params) so two `PostgreSQL`
/// URLs pointing at the same database can be compared even when one carries different
/// credentials or extra `?sslmode=...` parameters.
fn normalized_pg_authority(url: &str) -> String {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let without_query = without_scheme.split('?').next().unwrap_or(without_scheme);
    without_query
        .rsplit_once('@')
        .map_or(without_query, |(_, rest)| rest)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::normalized_pg_authority;

    #[test]
    fn normalized_authority_ignores_credentials() {
        assert_eq!(
            normalized_pg_authority("postgresql://u:p@host:5432/db"),
            normalized_pg_authority("postgresql://other:pw@host:5432/db")
        );
    }

    #[test]
    fn normalized_authority_ignores_query_params() {
        assert_eq!(
            normalized_pg_authority("postgresql://u:p@host:5432/db?sslmode=require"),
            normalized_pg_authority("postgresql://u:p@host:5432/db")
        );
    }

    #[test]
    fn normalized_authority_differs_on_database_name() {
        assert_ne!(
            normalized_pg_authority("postgresql://u:p@host:5432/db_audit"),
            normalized_pg_authority("postgresql://u:p@host:5432/db_objects")
        );
    }
}
