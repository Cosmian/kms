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
    ssl::SslRef,
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

/// Extract the peer certificate from the TLS stream and store it in request extensions.
pub(crate) fn extract_peer_certificate(cnx: &dyn Any, extensions: &mut Extensions) {
    // Check if the connection is a TLS connection.
    if let Some(cnx) = cnx.downcast_ref::<TlsStream<TcpStream>>() {
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
