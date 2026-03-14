use std::{
    fs::File,
    io::{BufReader, Read},
};

use reqwest::{ClientBuilder, Identity};

use super::{HttpClientConfig, error::result::HttpClientResult};

/// TLS client builder using native-tls (OpenSSL) for FIPS compliance
///
/// This function builds a TLS client with native-tls backend, which uses
/// the system's OpenSSL library. This approach ensures FIPS 140-3 compliance
/// when built against a FIPS-validated OpenSSL.
///
/// # Supported TLS Scenarios:
///
/// 1. **Default TLS Configuration**: Uses standard TLS settings with optional
///    invalid certificate acceptance based on `accept_invalid_certs`.
///
/// 2. **PEM Client Certificate Authentication**: When
///    `ssl_client_pem_cert_path` and `ssl_client_pem_key_path` are provided,
///    loads and configures client certificate authentication using PEM format
///    (FIPS compatible).
///
/// 3. **PKCS12 Client Certificate Authentication**: When
///    `ssl_client_pkcs12_path` is provided, loads and configures client
///    certificate authentication using PKCS12 format (non-FIPS mode only).
///
/// # Parameters
/// * `http_conf` - HTTP client configuration containing TLS settings
///
/// # Returns
/// * `HttpClientResult<ClientBuilder>` - Configured reqwest `ClientBuilder`
///   ready for use
///
/// # Limitations
/// - TEE certificate verification is not supported (would require rustls)
/// - Custom cipher suites are not supported on the client side (server-side
///   only)
pub(crate) fn build_tls_client(http_conf: &HttpClientConfig) -> HttpClientResult<ClientBuilder> {
    // Warn if advanced features are requested but not available
    if http_conf.verified_cert.is_some() {
        tracing::warn!(
            "TEE certificate verification is not supported with native-tls. Falling back to \
             standard certificate verification."
        );
    }

    if http_conf.cipher_suites.is_some() {
        tracing::warn!(
            "Custom cipher suites are not supported on the client side with native-tls. \
             Server-side cipher suite configuration is available through server configuration. \
             Using default cipher suites."
        );
    }

    // Build basic native-tls client
    let builder = ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs);

    // Handle client certificate authentication (PEM or PKCS#12)
    let builder = add_client_identity(builder, http_conf)?;

    Ok(builder)
}

/// Add client identity (certificate) to the builder if configured
fn add_client_identity(
    builder: ClientBuilder,
    http_conf: &HttpClientConfig,
) -> HttpClientResult<ClientBuilder> {
    // Prefer PEM (cert + key) if provided; otherwise fall back to PKCS#12
    let builder = if let (Some(cert_path), Some(key_path)) = (
        http_conf.ssl_client_pem_cert_path.as_deref(),
        http_conf.ssl_client_pem_key_path.as_deref(),
    ) {
        let mut cert_reader = BufReader::new(File::open(cert_path)?);
        let mut cert_bytes = vec![];
        cert_reader.read_to_end(&mut cert_bytes)?;

        let mut key_reader = BufReader::new(File::open(key_path)?);
        let mut key_bytes = vec![];
        key_reader.read_to_end(&mut key_bytes)?;

        // Create identity from certificate and key PEM files
        // from_pkcs8_pem expects (cert_pem, key_pem) separately
        let identity = Identity::from_pkcs8_pem(&cert_bytes, &key_bytes)?;
        builder.identity(identity)
    } else if let Some(ssl_client_pkcs12) = &http_conf.ssl_client_pkcs12_path {
        let mut pkcs12 = BufReader::new(File::open(ssl_client_pkcs12)?);
        let mut pkcs12_bytes = vec![];
        pkcs12.read_to_end(&mut pkcs12_bytes)?;
        let pkcs12 = Identity::from_pkcs12_der(
            &pkcs12_bytes,
            &http_conf
                .ssl_client_pkcs12_password
                .clone()
                .unwrap_or_default(),
        )?;
        builder.identity(pkcs12)
    } else {
        builder
    };

    Ok(builder)
}
