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
use openssl::{nid::Nid, x509::X509};

use crate::{
    
    error::KmsError,
   
    kms_bail,
   
    middlewares::{{AuthMethod, AuthenticatedUser},
    UserId},
    result::KResult,
,
};

/// Holds the peer certificate for the current connection.
#[derive(Debug, Clone)]
pub(super) struct PeerCertificate {
    /// The peer certificate.
    pub(crate) cert: X509,
}

/// Extract the peer certificate from the TLS stream and store it in request extensions.
pub(crate) fn extract_peer_certificate(cnx: &dyn Any, extensions: &mut Extensions) {
    // Check if the connection is a TLS connection.
    if let Some(cnx) = cnx.downcast_ref::<TlsStream<TcpStream>>() {
        // Get the peer certificate from the OpenSSL TLS connection.
        if let Some(cert) = cnx.ssl().peer_certificate() {
            // The certificate is already an openssl::X509 object
            extensions.insert(PeerCertificate { cert });
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

    // Extract the common name from the peer certificate.
    match certificate
        .cert
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
                Ok(AuthenticatedUser {
                    username: UserId::from(trimmed),
                    auth_method: AuthMethod::Mtls,
                })
            }
            Err(e) => kms_bail!("Client certificate common name is not UTF-8: {}", e),
        },
    }
}
