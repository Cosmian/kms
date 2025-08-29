use openssl::{
    pkcs12::ParsedPkcs12_2,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use tracing::trace;

use crate::{error::KmsError, result::KResult};

// TLS 1.3 cipher suites as defined in RFC 8446
const TLS13_CIPHER_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

/// Common TLS configuration for both HTTP and socket servers
pub struct TlsConfig<'a> {
    pub cipher_suites: Option<&'a str>,
    pub p12: &'a ParsedPkcs12_2,
    pub client_ca_cert_pem: Option<&'a [u8]>,
}

/// Create and configure a basic OpenSSL `SslAcceptorBuilder` with common TLS settings
///
/// This function handles the common configuration shared between HTTP and socket servers:
/// - Basic SSL acceptor setup with `mozilla_intermediate`
/// - TLS version configuration (1.2 and 1.3 support)
/// - Cipher suite configuration
/// - Server certificate and private key setup from PKCS#12
/// - CA certificate chain setup
///
/// # Arguments
/// * `config` - TLS configuration parameters
/// * `server_type` - Description of the server type for error messages
///
/// # Returns
/// An `SslAcceptorBuilder` ready for further customization
pub(crate) fn create_base_openssl_acceptor(
    config: &TlsConfig<'_>,
    server_type: &str,
) -> KResult<SslAcceptorBuilder> {
    trace!("create_base_openssl_acceptor: creating OpenSSL SslAcceptorBuilder for {server_type}");

    // Start with a basic TLS configuration
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

    // Support TLS 1.2 and 1.3 ciphers
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Clear any existing options that might interfere with TLS 1.3
    builder.clear_options(openssl::ssl::SslOptions::NO_TLSV1_3);

    // Configure cipher suites
    configure_cipher_suites(&mut builder, config.cipher_suites)?;

    // Configure the server certificate and private key from PKCS#12
    configure_server_certificate(&mut builder, config.p12, server_type)?;

    Ok(builder)
}

/// Configure cipher suites for the SSL acceptor
fn configure_cipher_suites(
    builder: &mut SslAcceptorBuilder,
    cipher_suites: Option<&str>,
) -> KResult<()> {
    if let Some(cipher_string) = cipher_suites {
        trace!(
            "configure_cipher_suites: Setting custom cipher string: {}",
            cipher_string
        );

        // Helper function to check if a cipher suite is TLS 1.3
        let is_tls13_cipher = |cipher: &str| -> bool { TLS13_CIPHER_SUITES.contains(&cipher) };

        // Separate cipher suites by TLS version
        let mut tls12_ciphers = Vec::new();
        let mut tls13_ciphers = Vec::new();

        for cipher in cipher_string.split(':') {
            let cipher = cipher.trim();
            if cipher.is_empty() {
                continue;
            }

            if cipher.starts_with("TLS_") && is_tls13_cipher(cipher) {
                // TLS 1.3 cipher suite identified by name
                tls13_ciphers.push(cipher.to_owned());
            } else {
                // TLS 1.2 or earlier cipher suite (including OpenSSL format names)
                tls12_ciphers.push(cipher.to_owned());
            }
        }

        // Configure TLS 1.2 cipher suites if any are present
        if !tls12_ciphers.is_empty() {
            let tls12_string = tls12_ciphers.join(":");
            trace!(
                "configure_cipher_suites: Setting TLS 1.2 cipher suites: {}",
                tls12_string
            );
            builder.set_cipher_list(&tls12_string)?;
        }

        // Configure TLS 1.3 cipher suites if any are present
        if !tls13_ciphers.is_empty() {
            let tls13_string = tls13_ciphers.join(":");
            trace!(
                "configure_cipher_suites: Setting TLS 1.3 cipher suites: {}",
                tls13_string
            );
            builder.set_ciphersuites(&tls13_string)?;
        }
    } else {
        // Use a broad cipher list for compatibility and enable TLS 1.3 cipher suites
        let tls13_string = TLS13_CIPHER_SUITES.join(":");
        trace!(
            "configure_cipher_suites: Using default cipher suites (mozilla_intermediate) and \
             adding TLS 1.3 cipher suites: {tls13_string}"
        );
        builder.set_ciphersuites(&tls13_string)?;
    }
    Ok(())
}

/// Configure server certificate and private key from PKCS#12
fn configure_server_certificate(
    builder: &mut SslAcceptorBuilder,
    p12: &ParsedPkcs12_2,
    server_type: &str,
) -> KResult<()> {
    let Some(server_cert) = &p12.cert else {
        return Err(KmsError::Certificate(format!(
            "{server_type}: no server certificate found in PKCS#12 file"
        )));
    };

    let Some(server_pkey) = &p12.pkey else {
        return Err(KmsError::Certificate(format!(
            "{server_type}: no private key found in PKCS#12 file"
        )));
    };

    builder.set_certificate(server_cert)?;
    builder.set_private_key(server_pkey)?;

    // Add CA certificates from the PKCS#12 chain
    if let Some(cas) = &p12.ca {
        for ca in cas {
            builder.add_extra_chain_cert(ca.to_owned())?;
        }
    }

    Ok(())
}

/// Configure client certificate verification
pub(crate) fn configure_client_cert_verification(
    builder: &mut SslAcceptorBuilder,
    ca_cert_pem: &[u8],
    server_type: &str,
) -> KResult<()> {
    trace!(
        "Configuring client certificate verification for {}",
        server_type
    );

    // Load the CA certificate for client verification
    let ca_cert = X509::from_pem(ca_cert_pem)?;
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
    store_builder.add_cert(ca_cert)?;
    let ca_store = store_builder.build();

    builder.set_verify_cert_store(ca_store)?;
    builder.set_verify(SslVerifyMode::PEER);

    Ok(())
}
