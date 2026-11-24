use std::path::Path;

use cosmian_logger::trace;
#[cfg(feature = "non-fips")]
use openssl::pkcs12::ParsedPkcs12_2;
use openssl::{
    pkey::PKey,
    ssl::{
        SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslOptions, SslSessionCacheMode,
        SslVerifyMode, SslVersion,
    },
    x509::{
        X509,
        store::{X509Lookup, X509StoreBuilder},
        verify::X509VerifyFlags,
    },
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
///
/// When `clients_crl_dir` is set, the leaf client certificate is checked against the CRL of
/// its issuer, loaded on demand from that OpenSSL hashed directory (`<subject-hash>.rN`, see
/// `openssl rehash`). The check is fail-closed: a missing or expired CRL for the issuer rejects
/// the client. New `.rN` files are picked up by later handshakes without rebuilding the
/// acceptor. Both the HTTP and the socket server use this function.
pub(crate) fn configure_client_cert_verification(
    builder: &mut SslAcceptorBuilder,
    ca_cert_pem: &[u8],
    server_type: &str,
    clients_crl_dir: Option<&Path>,
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

    if let Some(dir) = clients_crl_dir {
        let dir_str = dir.to_str().ok_or_else(|| {
            KmsError::ServerError(format!(
                "{server_type}: clients_crl_dir {} is not valid UTF-8",
                dir.display()
            ))
        })?;
        store_builder
            .add_lookup(X509Lookup::hash_dir())?
            .add_dir(dir_str, SslFiletype::PEM)?;
        store_builder.set_flags(X509VerifyFlags::CRL_CHECK)?;
    }

    let ca_store = store_builder.build();

    builder.set_verify_cert_store(ca_store)?;
    builder.set_verify(SslVerifyMode::PEER);

    // A client certificate is mapped to a KMS user using the chain OpenSSL verified during the
    // handshake (the enrolled-certificate check looks at every issuer in it), and a resumed
    // session does not keep that chain: every connection must do a full handshake.
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
    builder.set_options(SslOptions::NO_TICKET);
    builder.set_num_tickets(0)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::openssl::crl::{
        RevokedEntry, build_crl,
    };
    use openssl::{pkey::Private, ssl::SslConnector};
    use time::OffsetDateTime;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const CERTS: &str = "../../test_data/certificates/client_server";
    /// Client certificate (path without extension, `.crt` and `.key` exist) of two users.
    const USER: &str = "user/user.client.acme.com";
    const OWNER: &str = "owner/owner.client.acme.com";

    /// Whether an acceptor configured for client certificates has session resumption off:
    /// no session cache and no tickets.
    fn resumption_is_off() -> KResult<bool> {
        let ca = std::fs::read("../../test_data/certificates/client_server/ca/ca.crt")
            .map_err(|e| KmsError::ServerError(e.to_string()))?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        configure_client_cert_verification(&mut builder, &ca, "test", None)?;
        // `set_session_cache_mode` returns the mode that was in force
        let cache_off =
            builder.set_session_cache_mode(SslSessionCacheMode::SERVER) == SslSessionCacheMode::OFF;
        Ok(cache_off && builder.options().contains(SslOptions::NO_TICKET))
    }

    /// The user mapping needs the chain verified in the handshake, which a resumed session does
    /// not keep: acceptors that verify client certificates must not resume sessions.
    #[test]
    fn client_certificate_acceptors_do_not_resume_sessions() {
        assert!(matches!(resumption_is_off(), Ok(true)));
    }

    /// Write a CRL of the test CA revoking `revoked` as `<hash>.r<suffix>` in `dir`.
    fn write_crl(dir: &Path, suffix: u32, revoked: &[&str]) -> TestResult {
        let ca = X509::from_pem(&fs::read(format!("{CERTS}/ca/ca.crt"))?)?;
        let ca_key: PKey<Private> =
            PKey::private_key_from_pem(&fs::read(format!("{CERTS}/ca/ca.key"))?)?;
        let entries = revoked
            .iter()
            .map(|client| -> TestResult<RevokedEntry> {
                let cert = X509::from_pem(&fs::read(format!("{CERTS}/{client}.crt"))?)?;
                Ok(RevokedEntry {
                    serial_number: cert.serial_number().to_bn()?.to_vec(),
                    revocation_date: OffsetDateTime::now_utc(),
                    reason_code: None,
                    invalidity_date: None,
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        let crl = build_crl(&ca, &ca_key, &entries, u64::from(suffix) + 1, 1)?;
        fs::write(
            dir.join(format!("{:08x}.r{suffix}", ca.subject_name_hash())),
            crl.to_pem()?,
        )?;
        Ok(())
    }

    /// Serve `connections` TLS connections with one acceptor that checks client certificates
    /// against the CRLs in `crl_dir`; an accepted client receives `ok`.
    fn spawn_server(crl_dir: &Path, connections: usize) -> TestResult<SocketAddr> {
        let ca = fs::read(format!("{CERTS}/ca/ca.crt"))?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        builder.set_certificate_file(
            format!("{CERTS}/server/kmserver.acme.com.crt"),
            SslFiletype::PEM,
        )?;
        builder.set_private_key_file(
            format!("{CERTS}/server/kmserver.acme.com.key"),
            SslFiletype::PEM,
        )?;
        configure_client_cert_verification(&mut builder, &ca, "test", Some(crl_dir))?;
        let acceptor = builder.build();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        thread::spawn(move || {
            for stream in listener.incoming().take(connections).flatten() {
                if let Ok(mut tls) = acceptor.accept(stream) {
                    drop(tls.write_all(b"ok"));
                    drop(tls.shutdown());
                }
            }
        });
        Ok(addr)
    }

    /// Whether the server accepts `client`. With TLS 1.3 the client finishes its handshake
    /// before the server verifies the client certificate, so acceptance is proven by reading
    /// the server's `ok`; a rejection surfaces as an alert or EOF on that read.
    fn is_accepted(addr: SocketAddr, client: &str) -> TestResult<bool> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_ca_file(format!("{CERTS}/ca/ca.crt"))?;
        connector.set_certificate_file(format!("{CERTS}/{client}.crt"), SslFiletype::PEM)?;
        connector.set_private_key_file(format!("{CERTS}/{client}.key"), SslFiletype::PEM)?;
        let connector = connector.build();
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let config = connector.configure()?.verify_hostname(false);
        let Ok(mut tls) = config.connect("localhost", stream) else {
            return Ok(false);
        };
        let mut reply = [0_u8; 2];
        Ok(tls.read_exact(&mut reply).is_ok() && &reply == b"ok")
    }

    /// F-015: a revoked client certificate is rejected, the check is fail-closed when the
    /// issuer has no CRL, and a CRL added later (`.r1`) is honoured by the same acceptor
    /// without a restart. The socket server builds its acceptor with the same function
    /// (`configure_client_cert_verification`), so it is covered as well.
    #[test]
    fn revoked_client_certificates_are_rejected_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let addr = spawn_server(dir.path(), 4).unwrap();

        // No CRL for the issuer yet: fail-closed
        assert!(!is_accepted(addr, OWNER).unwrap());

        write_crl(dir.path(), 0, &[USER]).unwrap();
        assert!(!is_accepted(addr, USER).unwrap());
        assert!(is_accepted(addr, OWNER).unwrap());

        // OpenSSL keeps the CRL with the latest `thisUpdate` (one-second resolution)
        thread::sleep(Duration::from_millis(1100));
        write_crl(dir.path(), 1, &[USER, OWNER]).unwrap();
        assert!(!is_accepted(addr, OWNER).unwrap());
    }
}
