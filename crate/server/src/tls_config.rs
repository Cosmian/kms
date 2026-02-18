use cosmian_logger::trace;
#[cfg(feature = "non-fips")]
use openssl::pkcs12::ParsedPkcs12_2;
use openssl::{
    pkey::PKey,
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
];

/// Common TLS configuration for both HTTP and socket servers
pub struct TlsConfig<'a> {
    pub cipher_suites: Option<&'a str>,
    #[cfg(feature = "non-fips")]
    pub p12: Option<&'a ParsedPkcs12_2>,
    pub server_cert_pem: &'a [u8],
    pub server_key_pem: &'a [u8],
    pub server_chain_pem: Option<&'a [u8]>,
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

    // Configure the server certificate and private key
    #[cfg(feature = "non-fips")]
    {
        if let Some(p12) = config.p12 {
            configure_server_certificate_p12(&mut builder, p12, server_type)?;
            return Ok(builder);
        }
    }
    configure_server_certificate_pem(
        &mut builder,
        config.server_cert_pem,
        config.server_key_pem,
        config.server_chain_pem,
        server_type,
    )?;

    Ok(builder)
}

/// Configure cipher suites for the SSL acceptor
fn configure_cipher_suites(cipher_suites: Option<&str>) -> KResult<SslAcceptorBuilder> {
    let builder = if let Some(suites) = cipher_suites {
        trace!("configure_cipher_suites: Setting custom cipher string: {suites}");

        // Helper function to check if a cipher suite is TLS 1.3
        let is_tls13_cipher = |cipher: &str| -> bool { TLS13_CIPHER_SUITES.contains(&cipher) };

        // Parse and split cipher suites into TLS1.3 vs TLS1.2 buckets
        let (tls13_ciphers, tls12_ciphers): (Vec<&str>, Vec<&str>) = suites
            .split(':')
            .filter(|s| !s.trim().is_empty())
            .partition(|&cipher| is_tls13_cipher(cipher));

        // Choose baseline profile depending on whether TLS1.2 ciphers are requested
        // - mozilla_intermediate allows TLS1.2 and TLS1.3
        // - mozilla_modern is TLS1.3-only; keep it when only TLS1.3 ciphers are provided
        let mut builder = if tls12_ciphers.is_empty() {
            SslAcceptor::mozilla_modern_v5(SslMethod::tls())?
        } else {
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?
        };

        if !tls12_ciphers.is_empty() {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
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
#[cfg(feature = "non-fips")]
fn configure_server_certificate_p12(
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

/// Configure server certificate and private key from PEM files (FIPS mode)
fn configure_server_certificate_pem(
    builder: &mut SslAcceptorBuilder,
    cert_pem: &[u8],
    key_pem: &[u8],
    chain_pem: Option<&[u8]>,
    server_type: &str,
) -> KResult<()> {
    // Parse key
    let pkey = PKey::private_key_from_pem(key_pem)?;

    // Parse certificate(s). The provided cert PEM may include the chain after the leaf.
    let mut certs = X509::stack_from_pem(cert_pem)?;
    if certs.is_empty() {
        return Err(KmsError::Certificate(format!(
            "{server_type}: no server certificate found in PEM"
        )));
    }
    let server_cert = certs.remove(0);

    builder.set_certificate(&server_cert)?;
    builder.set_private_key(&pkey)?;

    // Add any remaining certs from the cert pem as chain
    for ca in certs {
        builder.add_extra_chain_cert(ca)?;
    }

    // If a separate chain pem is provided, add those as well
    if let Some(chain) = chain_pem {
        for ca in X509::stack_from_pem(chain)? {
            builder.add_extra_chain_cert(ca)?;
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
