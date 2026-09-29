//! Tests for mTLS database connections (`PostgreSQL` and `MySQL`)
//!
//! These tests validate URL parsing and TLS configuration builder logic
//! without requiring actual database servers or certificates.

use std::{env, path::PathBuf};

use url::Url;

use crate::result::KResult;

#[test]
fn test_postgresql_mtls_url_parsing() {
    // Test that PostgreSQL URLs with mTLS parameters are valid
    let url_str = "postgresql://user:pass@localhost:5432/testdb?\
                   sslmode=verify-full&\
                   sslrootcert=/path/to/ca.pem&\
                   sslcert=/path/to/client-cert.pem&\
                   sslkey=/path/to/client-key.pem";

    let url = Url::parse(url_str).expect("Failed to parse PostgreSQL mTLS URL");

    // Verify query parameters are present
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("sslmode").map(std::convert::AsRef::as_ref),
        Some("verify-full")
    );
    assert_eq!(
        params.get("sslrootcert").map(std::convert::AsRef::as_ref),
        Some("/path/to/ca.pem")
    );
    assert_eq!(
        params.get("sslcert").map(std::convert::AsRef::as_ref),
        Some("/path/to/client-cert.pem")
    );
    assert_eq!(
        params.get("sslkey").map(std::convert::AsRef::as_ref),
        Some("/path/to/client-key.pem")
    );
}

#[test]
fn test_postgresql_tls_modes() {
    // Test various SSL modes
    let modes = vec!["disable", "prefer", "require", "verify-ca", "verify-full"];

    for mode in modes {
        let url_str = format!("postgresql://user:pass@localhost/db?sslmode={mode}");
        let url = Url::parse(&url_str).expect("Failed to parse PostgreSQL URL");

        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            params.get("sslmode").map(std::convert::AsRef::as_ref),
            Some(mode)
        );
    }
}

#[test]
fn test_mysql_mtls_url_parsing() {
    // Test that MySQL URLs with mTLS parameters are valid
    let url_str = "mysql://user:pass@localhost:3306/testdb?\
                   ssl-mode=VERIFY_CA&\
                   ssl-ca=/path/to/ca.pem&\
                   ssl-client-identity=/path/to/client.p12&\
                   ssl-client-identity-password=secret";

    let url = Url::parse(url_str).expect("Failed to parse MySQL mTLS URL");

    // Verify query parameters are present
    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("ssl-mode").map(std::convert::AsRef::as_ref),
        Some("VERIFY_CA")
    );
    assert_eq!(
        params.get("ssl-ca").map(std::convert::AsRef::as_ref),
        Some("/path/to/ca.pem")
    );
    assert_eq!(
        params
            .get("ssl-client-identity")
            .map(std::convert::AsRef::as_ref),
        Some("/path/to/client.p12")
    );
    assert_eq!(
        params
            .get("ssl-client-identity-password")
            .map(std::convert::AsRef::as_ref),
        Some("secret")
    );
}

#[test]
fn test_mysql_tls_modes() {
    // Test various SSL modes for MySQL
    let modes = vec![
        "DISABLED",
        "PREFERRED",
        "REQUIRED",
        "VERIFY_CA",
        "VERIFY_IDENTITY",
    ];

    for mode in modes {
        let url_str = format!("mysql://user:pass@localhost/db?ssl-mode={mode}");
        let url = Url::parse(&url_str).expect("Failed to parse MySQL URL");

        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            params.get("ssl-mode").map(std::convert::AsRef::as_ref),
            Some(mode)
        );
    }
}

#[test]
fn test_mysql_alternative_param_names() {
    // Test that underscore variants work (ssl_mode vs ssl-mode)
    let url_str = "mysql://user:pass@localhost/db?\
                   ssl_mode=REQUIRED&\
                   ssl_ca=/ca.pem&\
                   ssl_client_identity=/client.p12&\
                   ssl_client_identity_password=pass";

    let url = Url::parse(url_str).expect("Failed to parse MySQL URL with underscores");

    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("ssl_mode").map(std::convert::AsRef::as_ref),
        Some("REQUIRED")
    );
    assert_eq!(
        params.get("ssl_ca").map(std::convert::AsRef::as_ref),
        Some("/ca.pem")
    );
    assert_eq!(
        params
            .get("ssl_client_identity")
            .map(std::convert::AsRef::as_ref),
        Some("/client.p12")
    );
}

#[test]
fn test_postgresql_basic_tls_url() {
    // Test basic TLS without client cert (server auth only)
    let url_str = "postgresql://user:pass@localhost/db?sslmode=require&sslrootcert=/ca.pem";
    let url = Url::parse(url_str).expect("Failed to parse PostgreSQL basic TLS URL");

    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("sslmode").map(std::convert::AsRef::as_ref),
        Some("require")
    );
    assert_eq!(
        params.get("sslrootcert").map(std::convert::AsRef::as_ref),
        Some("/ca.pem")
    );
    assert!(!params.contains_key("sslcert"));
    assert!(!params.contains_key("sslkey"));
}

#[test]
fn test_mysql_basic_tls_url() {
    // Test basic TLS without client cert (server auth only)
    let url_str = "mysql://user:pass@localhost/db?ssl-mode=REQUIRED&ssl-ca=/ca.pem";
    let url = Url::parse(url_str).expect("Failed to parse MySQL basic TLS URL");

    let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(
        params.get("ssl-mode").map(std::convert::AsRef::as_ref),
        Some("REQUIRED")
    );
    assert_eq!(
        params.get("ssl-ca").map(std::convert::AsRef::as_ref),
        Some("/ca.pem")
    );
    assert!(!params.contains_key("ssl-client-identity"));
}

/// Get the absolute path to a certificate file in the `test_data` directory
fn get_cert_path(relative_path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Cannot get parent directory")
        .parent()
        .expect("Cannot get parent of parent directory")
        .join("test_data")
        .join(relative_path)
}

/// Test real mTLS connection to `PostgreSQL`
///
/// This test validates that the KMS server can connect to `PostgreSQL` using mutual TLS
/// (client certificates). It uses `sslmode=require` which enforces TLS encryption but
/// does not verify the server certificate hostname (since we're connecting to 127.0.0.1
/// but the certificate has CN=postgres).
///
/// This test requires the postgres-mtls service from docker-compose.yml to be running:
/// ```bash
/// docker compose up -d postgres-mtls
/// ```
///
/// To run this test:
/// ```bash
/// cargo test --package cosmian_kms_server --lib test_postgresql_mtls_connection -- --ignored --nocapture
/// ```
#[ignore = "Requires postgres-mtls service running (docker compose up -d postgres-mtls)"]
#[tokio::test]
async fn test_db_postgresql_mtls_connection() -> KResult<()> {
    // Build PostgreSQL URL with properly encoded query parameters
    let ca_cert = get_cert_path("certificates/client_server/ca/ca.crt");
    let client_cert = get_cert_path("certificates/client_server/db/postgres-client.crt");
    let client_key = get_cert_path("certificates/client_server/db/postgres-client.key");

    let mut url =
        Url::parse("postgres://kms:kms@127.0.0.1:5433/kms").expect("Failed to parse base URL");
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("sslmode", "require");
        query.append_pair("sslrootcert", &ca_cert.to_string_lossy());
        query.append_pair("sslcert", &client_cert.to_string_lossy());
        query.append_pair("sslkey", &client_key.to_string_lossy());
    }
    let postgres_url = url.to_string();

    // Test via KMS instantiation which internally creates the database pool
    let config = crate::config::ClapConfig {
        db: crate::config::MainDBConfig {
            database_type: Some("postgresql".to_owned()),
            database_url: Some(postgres_url),
            sqlite_path: PathBuf::new(),
            clear_database: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let server_params = std::sync::Arc::new(crate::config::ServerParams::try_from(config)?);
    let _kms = crate::core::KMS::instantiate(server_params).await?;

    Ok(())
}

/// Test real mTLS connection to `MySQL`
///
/// This test validates that the KMS server can connect to `MySQL` using mutual TLS
/// (client certificates). It uses `ssl-mode=REQUIRED` which enforces TLS encryption but
/// does not verify the server certificate (since we're connecting to 127.0.0.1 but the
/// certificate has CN=mysql, and native-tls certificate verification is strict).
///
/// This test requires the mysql-mtls service from docker-compose.yml to be running:
/// ```bash
/// docker compose up -d mysql-mtls
/// ```
///
/// To run this test:
/// ```bash
/// cargo test --package cosmian_kms_server --lib test_mysql_mtls_connection -- --ignored --nocapture
/// ```
#[ignore = "Requires mysql-mtls service running (docker compose up -d mysql-mtls)"]
#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_db_mysql_mtls_connection() -> KResult<()> {
    // Build MySQL mTLS URL with actual certificate paths
    let ca_cert = get_cert_path("certificates/client_server/ca/ca.crt");
    let client_p12 = get_cert_path("certificates/client_server/db/mysql-client.p12");

    // Build URL with proper query parameters
    let mut url =
        Url::parse("mysql://kms:kms@127.0.0.1:3309/kms").expect("Failed to parse base URL");
    url.query_pairs_mut()
        .append_pair("ssl-mode", "REQUIRED")
        .append_pair("ssl-ca", &ca_cert.to_string_lossy())
        .append_pair("ssl-client-identity", &client_p12.to_string_lossy())
        .append_pair("ssl-client-identity-password", "password");

    let mysql_url = url.to_string();

    // Test via KMS instantiation which internally creates the database pool
    let config = crate::config::ClapConfig {
        db: crate::config::MainDBConfig {
            database_type: Some("mysql".to_owned()),
            database_url: Some(mysql_url),
            sqlite_path: PathBuf::new(),
            clear_database: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let server_params = std::sync::Arc::new(crate::config::ServerParams::try_from(config)?);
    let _kms = crate::core::KMS::instantiate(server_params).await?;

    Ok(())
}
