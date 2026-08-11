//! Shared `PostgreSQL` connection-pool construction: `sslmode` / TLS handling and multi-host URL
//! parsing.
//!
//! Used by both the object store's [`PgPool`](super::PgPool) and the audit backend's
//! `PgAuditSink`, so there is exactly one place in the crate that understands the KMS's
//! `PostgreSQL` URL dialect (multi-host URLs, `sslmode`, client-cert mTLS).

use std::collections::HashMap;

use deadpool_postgres::{Config as PgConfig, ManagerConfig, Pool, RecyclingMethod};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use tokio_postgres::NoTls;

use crate::error::DbError;

/// SSL-related query parameters that are handled via `MakeTlsConnector` and must be stripped
/// from the URL before it is passed to `deadpool-postgres`.
const SSL_PARAMS: &[&str] = &["sslmode", "sslrootcert", "sslcert", "sslkey"];

/// Extract query parameters from a `PostgreSQL` connection URL by splitting on `?`/`&`.
/// This avoids `Url::parse()` which cannot handle multi-host connection strings.
pub(crate) fn extract_query_params(url: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    params
}

/// Rebuild the connection URL, removing only SSL-related query parameters.
/// Other parameters like `target_session_attrs` are preserved for `tokio-postgres`.
pub(crate) fn rebuild_url_without_ssl_params(
    url: &str,
    params: &HashMap<String, String>,
) -> String {
    let base = url.split('?').next().unwrap_or(url);
    let non_ssl_params: Vec<String> = params
        .iter()
        .filter(|(k, _)| !SSL_PARAMS.contains(&k.as_str()))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if non_ssl_params.is_empty() {
        base.to_owned()
    } else {
        format!("{}?{}", base, non_ssl_params.join("&"))
    }
}

fn decode_pg_ssl_file_query_value(value: &str) -> String {
    // Keep the common fast path allocation-free.
    if !value.as_bytes().iter().any(|b| *b == b'%' || *b == b'+') {
        return value.to_owned();
    }

    // Decode query value semantics (`%xx` and `+`) without reparsing the full URL.
    // This is required when PostgreSQL URLs are split manually (multi-host support),
    // otherwise OpenSSL receives encoded file paths like `%2Fhome%2F...`.
    let encoded = format!("v={value}");
    url::form_urlencoded::parse(encoded.as_bytes())
        .find_map(|(k, v)| (k == "v").then(|| v.into_owned()))
        .unwrap_or_else(|| value.to_owned())
}

/// Builds a `deadpool-postgres` pool for `connection_url`, handling `sslmode`, multi-host URLs,
/// and mutual-TLS client certificates.
///
/// `recycling` trades off connection-liveness assurance against round trips: [`RecyclingMethod::Verified`]
/// runs a `simple_query("")` health check on every `pool.get()` (used by the object store, whose
/// pool is shared by every Actix worker); [`RecyclingMethod::Fast`] skips it (used by the
/// single-writer audit sink, whose `write_event` retry loop already covers a dead connection, so
/// paying for a liveness probe on every insert buys nothing the retry does not already cover).
pub(crate) fn build_pool(
    connection_url: &str,
    max_connections: Option<u32>,
    recycling: RecyclingMethod,
) -> Result<Pool, DbError> {
    // Extract query parameters manually instead of using Url::parse(),
    // which cannot handle multi-host PostgreSQL connection strings
    // (e.g. "postgresql://user:pass@host1:5432,host2:5432/db?target_session_attrs=read-write").
    let query_params = extract_query_params(connection_url);

    // Build a URL that strips only SSL-related params (handled via MakeTlsConnector)
    // but preserves other params like target_session_attrs for tokio-postgres.
    let clean_url_str = rebuild_url_without_ssl_params(connection_url, &query_params);

    let mut cfg = PgConfig::new();
    cfg.url = Some(clean_url_str);
    cfg.manager = Some(ManagerConfig {
        recycling_method: recycling,
    });

    // Pool sizing defaults: conservative pool tuned to CPU.
    // Keep behavior consistent with the MySQL backend.
    let default_conns: usize = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .saturating_mul(2)
        .min(10);
    let max_conns: usize = max_connections
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(default_conns);
    cfg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: max_conns,
        ..Default::default()
    });

    // Check sslmode parameter (disable, allow, prefer, require, verify-ca, verify-full)
    let sslmode = query_params.get("sslmode").map_or("prefer", String::as_str);

    if sslmode == "disable" {
        // Explicitly no TLS
        return cfg
            .create_pool(None, NoTls)
            .map_err(|e| DbError::DatabaseError(e.to_string()));
    }

    // Build TLS connector for require, verify-ca, verify-full, prefer, allow
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| DbError::DatabaseError(format!("TLS setup failed: {e}")))?;

    // Set verification mode based on sslmode
    match sslmode {
        "verify-full" => {
            // verify-full: verify certificate AND hostname
            builder.set_verify(SslVerifyMode::PEER);
        }
        "verify-ca" => {
            // verify-ca: verify certificate but NOT hostname
            builder.set_verify(SslVerifyMode::PEER);
            // For verify-ca, we don't want hostname verification
            // This is handled by not setting any hostname verification parameters
        }
        _ => {
            // require, prefer, allow: connect with TLS but don't verify cert
            builder.set_verify(SslVerifyMode::NONE);
        }
    }

    // Load CA cert if provided (sslrootcert)
    if let Some(ca_file) = query_params.get("sslrootcert") {
        let ca_file = decode_pg_ssl_file_query_value(ca_file.as_ref());
        builder
            .set_ca_file(ca_file.as_str())
            .map_err(|e| DbError::DatabaseError(format!("Failed to load CA: {e}")))?;
    }

    // Load client cert/key for mutual TLS (sslcert, sslkey)
    if let Some(cert_file) = query_params.get("sslcert") {
        let cert_file = decode_pg_ssl_file_query_value(cert_file.as_ref());
        builder
            .set_certificate_file(cert_file.as_str(), SslFiletype::PEM)
            .map_err(|e| DbError::DatabaseError(format!("Failed to load client cert: {e}")))?;
    }
    if let Some(key_file) = query_params.get("sslkey") {
        let key_file = decode_pg_ssl_file_query_value(key_file.as_ref());
        builder
            .set_private_key_file(key_file.as_str(), SslFiletype::PEM)
            .map_err(|e| DbError::DatabaseError(format!("Failed to load client key: {e}")))?;
    }

    let connector = MakeTlsConnector::new(builder.build());
    cfg.create_pool(None, connector)
        .map_err(|e| DbError::DatabaseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{extract_query_params, rebuild_url_without_ssl_params};

    #[test]
    fn test_extract_query_params_single_host() {
        let url = "postgresql://kms:kms@localhost:5432/kms?sslmode=require";
        let params = extract_query_params(url);
        assert_eq!(params.get("sslmode"), Some(&"require".to_owned()));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_extract_query_params_multi_host() {
        let url = "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write&sslmode=require";
        let params = extract_query_params(url);
        assert_eq!(
            params.get("target_session_attrs"),
            Some(&"read-write".to_owned())
        );
        assert_eq!(params.get("sslmode"), Some(&"require".to_owned()));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_extract_query_params_no_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms";
        let params = extract_query_params(url);
        assert!(params.is_empty());
    }

    #[test]
    fn test_rebuild_url_strips_only_ssl_params() {
        let url = "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write&sslmode=require&sslrootcert=/path/ca.pem";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(
            clean,
            "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write"
        );
    }

    #[test]
    fn test_rebuild_url_all_ssl_params_stripped() {
        let url = "postgresql://kms:kms@localhost:5432/kms?sslmode=require&sslcert=/c.pem&sslkey=/k.pem&sslrootcert=/ca.pem";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, "postgresql://kms:kms@localhost:5432/kms");
    }

    #[test]
    fn test_rebuild_url_preserves_non_ssl_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms?target_session_attrs=read-write&application_name=cosmian_kms";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        // Both non-SSL params should be preserved (order may vary)
        assert!(clean.contains("target_session_attrs=read-write"));
        assert!(clean.contains("application_name=cosmian_kms"));
        assert!(clean.starts_with("postgresql://kms:kms@localhost:5432/kms?"));
    }

    #[test]
    fn test_rebuild_url_no_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, url);
    }

    #[test]
    fn test_multi_host_url_preserved_in_rebuild() {
        let url = "postgresql://kms:kms@host1:5432,host2:5433,host3:5434/kms?target_session_attrs=read-write";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, url);
    }
}
