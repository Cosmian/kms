use std::{
    fs::File,
    io::{BufReader, Read},
};

use openssl::{
    pkcs12::Pkcs12,
    ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode},
    x509::X509,
};
use tracing::warn;

use super::{HttpClientConfig, error::result::HttpClientResult};

/// Map a TLS 1.2 IANA cipher suite name to its OpenSSL equivalent.
///
/// OpenSSL's `SSL_CTX_set_cipher_list` accepts OpenSSL-specific names
/// (e.g., `ECDHE-RSA-AES256-GCM-SHA384`), not IANA names
/// (e.g., `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`).
/// Returns `None` for unknown names; the caller should skip with a warning.
fn iana_to_openssl_tls12(iana: &str) -> Option<&'static str> {
    match iana {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => Some("ECDHE-RSA-AES128-SHA"),
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => Some("ECDHE-RSA-AES256-SHA"),
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => Some("ECDHE-RSA-AES128-SHA256"),
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => Some("ECDHE-ECDSA-AES128-SHA"),
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => Some("ECDHE-ECDSA-AES256-SHA"),
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => Some("ECDHE-ECDSA-AES128-SHA256"),
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => Some("AES128-GCM-SHA256"),
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => Some("AES256-GCM-SHA384"),
        "TLS_RSA_WITH_AES_128_CBC_SHA" => Some("AES128-SHA"),
        "TLS_RSA_WITH_AES_256_CBC_SHA" => Some("AES256-SHA"),
        "TLS_RSA_WITH_AES_128_CBC_SHA256" => Some("AES128-SHA256"),
        _ => None,
    }
}

/// Build an `SslConnectorBuilder` from the HTTP client configuration.
///
/// This replaces the former `reqwest`-based TLS builder. OpenSSL is used
/// exclusively, providing native PQC algorithm support (ML-DSA, ML-KEM,
/// SLH-DSA) through OpenSSL 3.6.2.
pub(crate) fn build_ssl_connector(
    http_conf: &HttpClientConfig,
) -> HttpClientResult<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    // Certificate verification
    if http_conf.accept_invalid_certs {
        builder.set_verify(SslVerifyMode::NONE);
    }

    // Add a specific CA certificate for server verification
    if let Some(ref verified_cert_path) = http_conf.verified_cert {
        let mut cert_file = BufReader::new(File::open(verified_cert_path)?);
        let mut cert_bytes = vec![];
        cert_file.read_to_end(&mut cert_bytes)?;
        let cert = X509::from_pem(&cert_bytes)?;
        builder.cert_store_mut().add_cert(cert)?;
    }

    // Client certificate authentication (PEM or PKCS#12)
    add_client_identity(&mut builder, http_conf)?;

    // Cipher suites configuration
    if let Some(ref cipher_suites) = http_conf.cipher_suites {
        configure_cipher_suites(&mut builder, cipher_suites);
    }

    Ok(builder)
}

/// Configure cipher suites on the SSL connector builder.
///
/// Separates TLS 1.3 ciphersuites (IANA names, set via `set_ciphersuites`) from
/// TLS 1.2 cipher suites (OpenSSL names, set via `set_cipher_list`).
/// Unrecognised or unsupported cipher names are skipped with a warning so that
/// the client always falls back to its default cipher list rather than failing.
fn configure_cipher_suites(builder: &mut SslConnectorBuilder, cipher_suites: &str) {
    // TLS 1.3 cipher names use IANA format (e.g. TLS_AES_256_GCM_SHA384) and
    // never contain "_WITH_", "ECDHE", or "DHE" in their names.
    let (tls13, tls12_iana): (Vec<&str>, Vec<&str>) = cipher_suites
        .split(':')
        .filter(|s| !s.is_empty())
        .partition(|s| {
            s.starts_with("TLS_")
                && !s.contains("_WITH_")
                && !s.contains("ECDHE")
                && !s.contains("DHE")
        });

    // TLS 1.3 ciphersuites — IANA names are used directly by OpenSSL.
    if !tls13.is_empty() {
        let list = tls13.join(":");
        if let Err(e) = builder.set_ciphersuites(&list) {
            warn!(
                "Failed to set TLS 1.3 ciphersuites '{}' (using defaults): {}",
                list, e
            );
        }
    }

    // TLS 1.2 ciphers — OpenSSL uses its own naming scheme, not IANA names.
    // Convert IANA names; pass through non-IANA entries as-is; skip unknowns.
    let tls12_openssl: Vec<&str> = tls12_iana
        .iter()
        .filter_map(|s| {
            if s.starts_with("TLS_") {
                iana_to_openssl_tls12(s).map_or_else(
                    || {
                        warn!("Unknown TLS 1.2 IANA cipher suite '{}' (skipping)", s);
                        None
                    },
                    Some,
                )
            } else {
                // Assume it's already in OpenSSL format.
                Some(*s)
            }
        })
        .collect();

    if !tls12_openssl.is_empty() {
        let list = tls12_openssl.join(":");
        if let Err(e) = builder.set_cipher_list(&list) {
            warn!(
                "Failed to set TLS 1.2 cipher list '{}' (using defaults): {}",
                list, e
            );
        }
    }
}

/// Add client identity (certificate + private key) to the SSL connector builder.
///
/// Supports PEM (cert + key files) and PKCS#12 (single file with password).
fn add_client_identity(
    builder: &mut SslConnectorBuilder,
    http_conf: &HttpClientConfig,
) -> HttpClientResult<()> {
    if let (Some(cert_path), Some(key_path)) = (
        http_conf.tls_client_pem_cert_path.as_deref(),
        http_conf.tls_client_pem_key_path.as_deref(),
    ) {
        // PEM certificate chain
        builder.set_certificate_chain_file(cert_path)?;
        // PEM private key
        builder.set_private_key_file(key_path, openssl::ssl::SslFiletype::PEM)?;
        // Verify the private key matches the certificate
        builder.check_private_key()?;
    } else if let Some(pkcs12_path) = &http_conf.tls_client_pkcs12_path {
        let mut pkcs12_file = BufReader::new(File::open(pkcs12_path)?);
        let mut pkcs12_bytes = vec![];
        pkcs12_file.read_to_end(&mut pkcs12_bytes)?;

        let password = http_conf
            .tls_client_pkcs12_password
            .as_deref()
            .unwrap_or_default();

        let pkcs12 = Pkcs12::from_der(&pkcs12_bytes)?;
        let parsed = pkcs12.parse2(password)?;

        if let Some(cert) = parsed.cert {
            builder.set_certificate(&cert)?;
        }
        if let Some(pkey) = parsed.pkey {
            builder.set_private_key(&pkey)?;
        }
        if let Some(chain) = parsed.ca {
            for ca_cert in chain {
                builder.add_extra_chain_cert(ca_cert)?;
            }
        }
        builder.check_private_key()?;
    }

    Ok(())
}
