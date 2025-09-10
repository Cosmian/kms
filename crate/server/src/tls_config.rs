use cosmian_logger::trace;
use openssl::{
    pkcs12::ParsedPkcs12_2,
    ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};

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

    // Configure cipher suites
    let mut builder = configure_cipher_suites(config.cipher_suites)?;

    // Configure the server certificate and private key from PKCS#12
    configure_server_certificate(&mut builder, config.p12, server_type)?;

    Ok(builder)
}

/// Configure cipher suites for the SSL acceptor
fn configure_cipher_suites(cipher_suites: Option<&str>) -> KResult<SslAcceptorBuilder> {
    let builder = if let Some(suites) = cipher_suites {
        trace!("configure_cipher_suites: Setting custom cipher string: {suites}");

        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;

        // Helper function to check if a cipher suite is TLS 1.3
        let is_tls13_cipher = |cipher: &str| -> bool { TLS13_CIPHER_SUITES.contains(&cipher) };

        // Parse and configure cipher suites
        let (tls13_ciphers, tls12_ciphers): (Vec<&str>, Vec<&str>) = suites
            .split(':')
            .filter(|s| !s.trim().is_empty())
            .partition(|&cipher| is_tls13_cipher(cipher));

        if !tls12_ciphers.is_empty() {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_cipher_list(&tls12_ciphers.join(":"))?;
        }

        if !tls13_ciphers.is_empty() {
            if tls12_ciphers.is_empty() {
                builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            }
            builder.set_ciphersuites(&tls13_ciphers.join(":"))?;
        }
        builder
    } else {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        trace!("configure_cipher_suites: Enable default cipher suites (mozilla_intermediate_v5)");
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder
    };
    Ok(builder)
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

    // Load the CA certificates for client verification
    let ca_certs = X509::stack_from_pem(ca_cert_pem)?;
    let mut store_builder = X509StoreBuilder::new()?;

    // Add all CA certificates to the store
    for ca_cert in ca_certs {
        store_builder.add_cert(ca_cert)?;
    }

    let ca_store = store_builder.build();

    builder.set_verify_cert_store(ca_store)?;
    builder.set_verify(SslVerifyMode::PEER);

    Ok(())
}
