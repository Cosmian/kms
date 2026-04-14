//! Tests for the KMS configuration wizard.
//!
//! Since the wizard relies on interactive terminal prompts, the tests focus on
//! the subsystems that do not require user interaction:
//!
//! - [`cert_gen`] — self-signed PKI generation (CA + server + client certs)
//! - TOML round-trip for the assembled [`crate::config::ClapConfig`]

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    unreachable_pub
)]

use std::path::{Path, PathBuf};

use openssl::{nid::Nid, pkey::PKey, x509::X509};
use tempfile::TempDir;

use super::cert_gen::{CertGenOptions, generate_self_signed_pki};
use crate::config::{ClapConfig, HttpConfig, MainDBConfig, TlsConfig};

// ── cert_gen tests ────────────────────────────────────────────────────────────

/// All five PEM files (ca.crt, server.crt, server.key, client.crt, client.key)
/// must be created in the requested output directory.
#[test]
fn test_generate_self_signed_pki_creates_all_files() {
    let tmp = TempDir::new().expect("failed to create temp dir");

    let opts = CertGenOptions {
        output_dir: tmp.path().to_path_buf(),
        ca_cn: "Test CA".to_owned(),
        server_cn: "localhost".to_owned(),
        client_cn: "test-client".to_owned(),
        // Use short validity so the test is fast; actual values don't matter here.
        ca_validity_days: 3,
        server_validity_days: 2,
        client_validity_days: 2,
    };

    let paths = generate_self_signed_pki(&opts).expect("cert generation should succeed");

    assert!(paths.ca_cert.exists(), "ca.crt must exist");
    assert!(paths.server_cert.exists(), "server.crt must exist");
    assert!(paths.server_key.exists(), "server.key must exist");
    assert!(paths.client_cert.exists(), "client.crt must exist");

    // All written files must be non-empty.
    for p in [
        &paths.ca_cert,
        &paths.server_cert,
        &paths.server_key,
        &paths.client_cert,
    ] {
        assert!(
            std::fs::metadata(p).unwrap().len() > 0,
            "{} must not be empty",
            p.display()
        );
    }
}

/// Generated PEM files must be parseable by openssl and carry the expected
/// Common Name (CN) values.
#[test]
fn test_generated_certs_have_correct_common_names() {
    let tmp = TempDir::new().expect("failed to create temp dir");

    let opts = CertGenOptions {
        output_dir: tmp.path().to_path_buf(),
        ca_cn: "My Test CA".to_owned(),
        server_cn: "kms.example.com".to_owned(),
        client_cn: "client.example.com".to_owned(),
        ca_validity_days: 3,
        server_validity_days: 2,
        client_validity_days: 2,
    };

    let paths = generate_self_signed_pki(&opts).expect("cert generation should succeed");

    let ca_cert =
        X509::from_pem(&std::fs::read(&paths.ca_cert).unwrap()).expect("CA cert must be valid PEM");
    let server_cert = X509::from_pem(&std::fs::read(&paths.server_cert).unwrap())
        .expect("server cert must be valid PEM");
    let client_cert = X509::from_pem(&std::fs::read(&paths.client_cert).unwrap())
        .expect("client cert must be valid PEM");

    let cn_of = |cert: &X509| {
        cert.subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
    };

    assert_eq!(cn_of(&ca_cert), "My Test CA");
    assert_eq!(cn_of(&server_cert), "kms.example.com");
    assert_eq!(cn_of(&client_cert), "client.example.com");
}

/// The CA must be self-signed and server/client leaf certs must be issued by
/// that CA (issuer CN matches CA subject CN, signature verifies).
#[test]
fn test_generated_cert_chain_is_valid() {
    let tmp = TempDir::new().expect("failed to create temp dir");

    let opts = CertGenOptions {
        output_dir: tmp.path().to_path_buf(),
        ca_validity_days: 3,
        server_validity_days: 2,
        client_validity_days: 2,
        ..CertGenOptions::default()
    };

    let paths = generate_self_signed_pki(&opts).expect("cert generation should succeed");

    let ca_cert = X509::from_pem(&std::fs::read(&paths.ca_cert).unwrap()).unwrap();
    let server_cert = X509::from_pem(&std::fs::read(&paths.server_cert).unwrap()).unwrap();
    let client_cert = X509::from_pem(&std::fs::read(&paths.client_cert).unwrap()).unwrap();
    let server_key =
        PKey::private_key_from_pem(&std::fs::read(&paths.server_key).unwrap()).unwrap();

    let cn_of = |x: &openssl::x509::X509NameRef| {
        x.entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
    };

    // CA must be self-signed: issuer CN == subject CN
    assert_eq!(
        cn_of(ca_cert.subject_name()),
        cn_of(ca_cert.issuer_name()),
        "CA must be self-signed"
    );

    // Leaf certs must have the CA as issuer
    let ca_cn = cn_of(ca_cert.subject_name());
    assert_eq!(
        cn_of(server_cert.issuer_name()),
        ca_cn,
        "server cert issuer must be the CA"
    );
    assert_eq!(
        cn_of(client_cert.issuer_name()),
        ca_cn,
        "client cert issuer must be the CA"
    );

    // Cryptographic signature check: leaf certs must verify against the CA public key.
    let ca_pubkey = ca_cert.public_key().unwrap();
    assert!(
        server_cert.verify(&ca_pubkey).unwrap(),
        "server cert signature must verify with CA public key"
    );
    assert!(
        client_cert.verify(&ca_pubkey).unwrap(),
        "client cert signature must verify with CA public key"
    );

    // Server private key must match the server certificate's public key.
    assert!(
        server_cert.public_key().unwrap().public_eq(&server_key),
        "server private key must correspond to the server certificate"
    );
}

/// Each call to `generate_self_signed_pki` must produce distinct serial numbers
/// so that TLS clients do not reject the certificates.
#[test]
fn test_generated_certs_have_unique_serials() {
    let tmp = TempDir::new().expect("failed to create temp dir");

    let opts = CertGenOptions {
        output_dir: tmp.path().to_path_buf(),
        ca_validity_days: 3,
        server_validity_days: 2,
        client_validity_days: 2,
        ..CertGenOptions::default()
    };

    let paths = generate_self_signed_pki(&opts).expect("cert generation should succeed");

    let ca_cert = X509::from_pem(&std::fs::read(&paths.ca_cert).unwrap()).unwrap();
    let server_cert = X509::from_pem(&std::fs::read(&paths.server_cert).unwrap()).unwrap();
    let client_cert = X509::from_pem(&std::fs::read(&paths.client_cert).unwrap()).unwrap();

    let serial_hex = |cert: &X509| -> String {
        cert.serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_string()
    };

    let ca_serial = serial_hex(&ca_cert);
    let server_serial = serial_hex(&server_cert);
    let client_serial = serial_hex(&client_cert);

    assert_ne!(
        ca_serial, server_serial,
        "CA and server serials must differ"
    );
    assert_ne!(
        server_serial, client_serial,
        "server and client serials must differ"
    );
    assert_ne!(
        ca_serial, client_serial,
        "CA and client serials must differ"
    );
}

// ── TOML round-trip ───────────────────────────────────────────────────────────

/// A `ClapConfig` assembled by the wizard must survive a TOML serialise →
/// deserialise round-trip with all field values intact.
#[test]
fn test_config_toml_round_trip_preserves_values() {
    let original = ClapConfig {
        default_username: "operator".to_owned(),
        force_default_username: true,
        http: HttpConfig {
            port: 8443,
            hostname: "127.0.0.1".to_owned(),
            api_token_id: None,
            rate_limit_per_second: None,
            cors_allowed_origins: None,
        },
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: PathBuf::from("/tmp/test-kms"),
            clear_database: false,
            ..MainDBConfig::default()
        },
        tls: TlsConfig {
            tls_cert_file: Some(PathBuf::from("/etc/cosmian/server.crt")),
            tls_key_file: Some(PathBuf::from("/etc/cosmian/server.key")),
            clients_ca_cert_file: Some(PathBuf::from("/etc/cosmian/ca.crt")),
            ..TlsConfig::default()
        },
        kms_public_url: Some("https://kms.example.com".to_owned()),
        ms_dke_service_url: Some("https://kms.example.com/ms_dke".to_owned()),
        ..ClapConfig::default()
    };

    let toml_str =
        toml::to_string_pretty(&original).expect("ClapConfig must serialise to TOML without error");

    // Must be non-empty and contain expected keys.
    assert!(!toml_str.is_empty());
    assert!(toml_str.contains("force_default_username"));

    let restored: ClapConfig =
        toml::from_str(&toml_str).expect("ClapConfig must round-trip through TOML");

    assert_eq!(restored.default_username, "operator");
    assert!(restored.force_default_username);
    assert_eq!(restored.http.port, 8443);
    assert_eq!(restored.http.hostname, "127.0.0.1");
    assert_eq!(restored.db.database_type.as_deref(), Some("sqlite"));
    assert_eq!(restored.db.sqlite_path, PathBuf::from("/tmp/test-kms"));
    assert_eq!(
        restored.tls.tls_cert_file.as_deref(),
        Some(Path::new("/etc/cosmian/server.crt"))
    );
    assert_eq!(
        restored.tls.tls_key_file.as_deref(),
        Some(Path::new("/etc/cosmian/server.key"))
    );
    assert_eq!(
        restored.tls.clients_ca_cert_file.as_deref(),
        Some(Path::new("/etc/cosmian/ca.crt"))
    );
    assert_eq!(
        restored.kms_public_url.as_deref(),
        Some("https://kms.example.com")
    );
    assert_eq!(
        restored.ms_dke_service_url.as_deref(),
        Some("https://kms.example.com/ms_dke")
    );
}

/// Default `ClapConfig` must also round-trip cleanly (no panics, no data loss
/// of defaults such as the default username).
#[test]
fn test_config_toml_round_trip_default() {
    let original = ClapConfig::default();

    let toml_str = toml::to_string_pretty(&original)
        .expect("default ClapConfig must serialise to TOML without error");

    let restored: ClapConfig =
        toml::from_str(&toml_str).expect("default ClapConfig must round-trip through TOML");

    assert_eq!(restored.default_username, original.default_username);
    assert_eq!(restored.http.port, original.http.port);
    assert_eq!(restored.http.hostname, original.http.hostname);
}
