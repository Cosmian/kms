use std::{
    fs::File,
    io::{BufReader, Read},
};

use openssl::{
    pkcs12::Pkcs12,
    ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVerifyMode},
    x509::X509,
};

use super::{HttpClientConfig, error::result::HttpClientResult};

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
        // Split TLS 1.3 ciphersuites from TLS 1.2 cipher list
        let (tls13, tls12): (Vec<&str>, Vec<&str>) = cipher_suites
            .split(':')
            .partition(|s| s.starts_with("TLS_") && !s.contains("ECDHE") && !s.contains("RSA"));

        if !tls13.is_empty() {
            builder.set_ciphersuites(&tls13.join(":"))?;
        }
        if !tls12.is_empty() {
            builder.set_cipher_list(&tls12.join(":"))?;
        }
    }

    Ok(builder)
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
