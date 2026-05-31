use std::{
    fs::File,
    io::{BufReader, Read},
};

use reqwest::{ClientBuilder, Identity};

use super::{HttpClientConfig, error::result::HttpClientResult};

/// TLS client builder.
///
/// PEM client certificates use the rustls connector (avoids Windows/SChannel
/// limitations with PEM cert+key authentication). PKCS#12 falls back to the
/// native-tls connector.
pub(crate) fn build_tls_client(http_conf: &HttpClientConfig) -> HttpClientResult<ClientBuilder> {
    let builder = ClientBuilder::new().danger_accept_invalid_certs(http_conf.accept_invalid_certs);

    // Handle client certificate authentication (PEM or PKCS#12)
    let builder = add_client_identity(builder, http_conf)?;

    Ok(builder)
}

/// Add client identity (certificate) to the builder if configured.
///
/// PEM certs use the rustls connector (avoids Windows `SChannel` limitations
/// with PEM client certificates). PKCS#12 uses the native-tls connector.
fn add_client_identity(
    builder: ClientBuilder,
    http_conf: &HttpClientConfig,
) -> HttpClientResult<ClientBuilder> {
    // Prefer PEM (cert + key) if provided; otherwise fall back to PKCS#12
    let builder = if let (Some(cert_path), Some(key_path)) = (
        http_conf.tls_client_pem_cert_path.as_deref(),
        http_conf.tls_client_pem_key_path.as_deref(),
    ) {
        let mut cert_reader = BufReader::new(File::open(cert_path)?);
        let mut cert_bytes = vec![];
        cert_reader.read_to_end(&mut cert_bytes)?;

        let mut key_reader = BufReader::new(File::open(key_path)?);
        let mut key_bytes = vec![];
        key_reader.read_to_end(&mut key_bytes)?;

        // Concatenate cert + key PEM for rustls Identity::from_pem()
        let mut combined = cert_bytes;
        combined.push(b'\n');
        combined.extend_from_slice(&key_bytes);

        // Use rustls connector — avoids SChannel PEM limitations on Windows
        let identity = Identity::from_pem(&combined)?;
        builder.use_rustls_tls().identity(identity)
    } else if let Some(pkcs12_path) = &http_conf.tls_client_pkcs12_path {
        let mut pkcs12 = BufReader::new(File::open(pkcs12_path)?);
        let mut pkcs12_bytes = vec![];
        pkcs12.read_to_end(&mut pkcs12_bytes)?;
        let pkcs12 = Identity::from_pkcs12_der(
            &pkcs12_bytes,
            &http_conf
                .tls_client_pkcs12_password
                .clone()
                .unwrap_or_default(),
        )?;
        builder.identity(pkcs12)
    } else {
        // No client cert — use rustls for cross-platform consistency
        builder.use_rustls_tls()
    };

    Ok(builder)
}
