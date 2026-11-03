//! TLS Authentication Middleware
//!
//! This module provides TLS client certificate-based authentication for the KMS server.
//! It extracts client certificates from TLS connections and validates them to authenticate
//! users based on the certificate's Common Name (CN) field.

use std::any::Any;

use actix_tls::accept::openssl::TlsStream;
use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{Extensions, ServiceRequest, ServiceResponse},
    middleware::Next,
    rt::net::TcpStream,
};
use cosmian_logger::{debug, trace};
use openssl::{
    nid::Nid,
    ssl::{SslRef, SslVersion},
    x509::{X509, X509Ref},
};
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};

use crate::{
    core::operations::certify::template::ENROLLED_CERTIFICATE_POLICY_OID,
    error::KmsError,
    kms_bail,
    middlewares::{AuthMethod, AuthenticatedUser, UserId, reject_reserved_service_identity},
    result::KResult,
};

/// Holds the peer certificate for the current connection.
#[derive(Debug, Clone)]
pub(crate) struct PeerCertificate {
    /// The peer certificate.
    pub(crate) cert: X509,
    /// The KMS user `cert` maps to, resolved once per connection by
    /// [`user_from_client_certificate`]; the refusal reason when it maps to none.
    pub(crate) user: Result<UserId, String>,
}

/// The `tls-unique` channel binding (RFC 5929 §3.1) of the current TLS connection, checked by
/// EST against the CSR `challengePassword` (RFC 7030 §3.5). Absent when undefined (TLS 1.3).
#[derive(Debug, Clone)]
pub(crate) struct TlsUnique(pub(crate) Vec<u8>);

/// The first `Finished` message of the connection's handshake: the client's in a full
/// handshake, the server's in a resumed one (RFC 5929 §3.1). Only TLS 1.2 is supported: TLS 1.3
/// does not define tls-unique (RFC 9266) and older versions are not served.
pub(crate) fn tls_unique(ssl: &SslRef) -> Option<Vec<u8>> {
    if ssl.version2() != Some(SslVersion::TLS1_2) {
        return None;
    }
    let mut buf = [0_u8; 64];
    let len = if ssl.session_reused() {
        ssl.finished(&mut buf)
    } else {
        ssl.peer_finished(&mut buf)
    };
    buf.get(..len)
        .filter(|finished| !finished.is_empty())
        .map(<[u8]>::to_vec)
}

/// The certificates above the leaf of a TLS connection's client certificate chain.
///
/// This is the chain OpenSSL verified. Session resumption is off on every client-certificate
/// acceptor (`tls_config.rs`), so it is always present; the peer-sent chain fallback is defence
/// in depth. `None` when OpenSSL kept no chain at all; callers must then refuse to map the
/// certificate to a user.
pub(crate) fn verified_issuers(ssl: &SslRef) -> Option<Vec<X509>> {
    if let Some(chain) = ssl.verified_chain() {
        return Some(chain.iter().skip(1).map(ToOwned::to_owned).collect());
    }
    ssl.peer_cert_chain()
        .map(|chain| chain.iter().map(ToOwned::to_owned).collect())
}

/// Extract the per-connection TLS data (peer certificate, `tls-unique` channel binding) from
/// the TLS stream and store it in the connection extensions.
pub(crate) fn extract_peer_certificate(cnx: &dyn Any, extensions: &mut Extensions) {
    // Check if the connection is a TLS connection.
    if let Some(cnx) = cnx.downcast_ref::<TlsStream<TcpStream>>() {
        if let Some(binding) = tls_unique(cnx.ssl()) {
            extensions.insert(TlsUnique(binding));
        }
        // Get the peer certificate from the OpenSSL TLS connection.
        if let Some(cert) = cnx.ssl().peer_certificate() {
            // The certificate and its chain are fixed for the connection: map them to a user once.
            let user = user_from_client_certificate(&cert, verified_issuers(cnx.ssl()).as_deref())
                .map_err(|e| e.to_string());
            extensions.insert(PeerCertificate { cert, user });
        }
    }
}

/// TLS client-certificate authentication middleware.
///
/// Extracts the Common Name (CN) from the peer certificate and injects it as
/// [`AuthenticatedUser`] in the request extensions. Skips authentication if a
/// user was already injected by an earlier middleware in the chain.
///
/// Use with [`actix_web::middleware::from_fn`]:
/// ```ignore
/// app.wrap(actix_web::middleware::from_fn(tls_auth_fn))
/// ```
pub(crate) async fn tls_auth_fn<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    trace!("TLS Authentication...");
    if req.extensions().contains::<AuthenticatedUser>() {
        debug!("TLS: an authenticated user was already present; skipping certificate check");
    } else {
        match tls_auth(&req) {
            Ok(user) => {
                req.extensions_mut().insert(user);
            }
            Err(e) => {
                debug!("Client certificate authentication failed: {e:?}");
            }
        }
    }
    next.call(req).await
}

fn tls_auth(req: &ServiceRequest) -> KResult<AuthenticatedUser> {
    // Get the peer certificate from the context of the request.
    let Some(certificate) = req.conn_data::<PeerCertificate>() else {
        // Log that the peer certificate is not present.
        trace!("TLS Authentication: no peer certificate found");
        return Err(KmsError::InvalidRequest(
            "TLS Authentication: no peer certificate found".to_owned(),
        ));
    };

    Ok(AuthenticatedUser {
        username: certificate.user.clone().map_err(KmsError::InvalidRequest)?,
        auth_method: AuthMethod::Mtls,
    })
}

/// `true` when `certificate` carries the [`ENROLLED_CERTIFICATE_POLICY_OID`] stamped on
/// certificates issued through EST / SCEP. Fails closed when the certificate cannot be parsed.
pub(crate) fn is_enrollment_issued(certificate: &X509Ref) -> KResult<bool> {
    let der = certificate.to_der()?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|e| {
        KmsError::InvalidRequest(format!("cannot inspect the client certificate: {e}"))
    })?;
    Ok(parsed
        .iter_extensions()
        .any(|ext| match ext.parsed_extension() {
            ParsedExtension::CertificatePolicies(policies) => policies
                .iter()
                .any(|p| p.policy_id.to_id_string() == ENROLLED_CERTIFICATE_POLICY_OID),
            _ => false,
        }))
}

/// Derive the KMS username from a client certificate's Common Name.
///
/// Shared by the HTTPS mTLS middleware and the KMIP socket server so both apply the same
/// rules: the CN must be present, UTF-8, non-empty, not the `*` wildcard, not a reserved
/// internal service identity, and neither the certificate nor any issuer in its verified chain
/// may have been issued through EST / SCEP enrollment. A device chooses its own CN in its CSR,
/// so an enrolled certificate is a device identity only: it can renew itself over EST but never
/// authenticates as a KMS user, and neither can anything signed by a certificate it obtained.
pub(crate) fn user_from_client_certificate(
    certificate: &X509Ref,
    issuers: Option<&[X509]>,
) -> KResult<UserId> {
    let Some(issuers) = issuers else {
        kms_bail!(
            "Client certificate chain is not available (resumed TLS session?); refusing to \
             map the certificate to a user"
        );
    };
    if is_enrollment_issued(certificate)?
        || issuers.iter().try_fold(false, |found, issuer| {
            is_enrollment_issued(issuer).map(|marked| found || marked)
        })?
    {
        kms_bail!(
            "Client certificate was issued through EST/SCEP enrollment and cannot authenticate \
             as a KMS user; access denied"
        );
    }
    match certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
    {
        None => kms_bail!("Client certificate has no common name"),
        Some(cn) => match cn.data().to_string() {
            Ok(username) => {
                let trimmed = username.trim();
                if trimmed.is_empty() {
                    kms_bail!("Client certificate CN is empty; access denied");
                }
                if trimmed == "*" {
                    kms_bail!(
                        "Client certificate CN '{}' is a wildcard and not a valid username; \
                         access denied",
                        username
                    );
                }
                trace!("Client certificate common name: {}", username);
                let username = UserId::from(trimmed);
                reject_reserved_service_identity(&username)?;
                Ok(username)
            }
            Err(e) => kms_bail!("Client certificate common name is not UTF-8: {}", e),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // tests: a panic is the failure signal
mod tests {
    use std::{
        net::{TcpListener, TcpStream},
        thread,
    };

    use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};

    use super::*;

    const SERVER_DIR: &str = "../../test_data/certificates/client_server/server";

    /// Run one handshake at `version`; return the server-side `tls_unique` and the client's own
    /// `Finished` message.
    fn handshake(version: SslVersion) -> (Option<Vec<u8>>, Vec<u8>) {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate_chain_file(format!("{SERVER_DIR}/kmserver.acme.com.crt"))
                .unwrap();
            acceptor
                .set_private_key_file(
                    format!("{SERVER_DIR}/kmserver.acme.com.key"),
                    SslFiletype::PEM,
                )
                .unwrap();
            acceptor.set_min_proto_version(Some(version)).unwrap();
            acceptor.set_max_proto_version(Some(version)).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let stream = acceptor.build().accept(socket).unwrap();
            tls_unique(stream.ssl())
        });
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_max_proto_version(Some(version)).unwrap();
        let client = connector
            .build()
            .configure()
            .unwrap()
            .verify_hostname(false)
            .connect("localhost", TcpStream::connect(addr).unwrap())
            .unwrap();
        let mut buf = [0_u8; 64];
        let len = client.ssl().finished(&mut buf);
        let server_side = server.join().unwrap();
        (server_side, buf.get(..len).unwrap().to_vec())
    }

    #[test]
    fn tls12_tls_unique_is_the_client_finished_message() {
        let (server_side, client_finished) = handshake(SslVersion::TLS1_2);
        assert!(!client_finished.is_empty());
        assert_eq!(server_side, Some(client_finished));
    }

    #[test]
    fn tls13_has_no_tls_unique() {
        assert_eq!(handshake(SslVersion::TLS1_3).0, None);
    }
}
