//! SSL/TLS Authentication Middleware
//!
//! This module provides SSL/TLS client certificate-based authentication for the KMS server.
//! It extracts client certificates from TLS connections and validates them to authenticate
//! users based on the certificate's Common Name (CN) field.

use std::{
    any::Any,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_tls::accept::openssl::TlsStream;
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{Extensions, ServiceRequest, ServiceResponse},
    rt::net::TcpStream,
};
use cosmian_logger::{debug, trace};
use futures::{
    Future,
    future::{Ready, ok},
};
use openssl::{nid::Nid, x509::X509};

use crate::{error::KmsError, kms_bail, middlewares::AuthenticatedUser, result::KResult};

/// The extension struct holding the peer certificate during the connection.
///
/// This struct stores the peer certificate in the request context.
#[derive(Debug, Clone)]
pub(super) struct PeerCertificate {
    /// The peer certificate.
    pub(crate) cert: X509,
}

/// Extract the peer certificate from the TLS stream and pass it to middleware.
///
/// This function extracts the peer certificate from the TLS stream and passes it to the middleware.
/// The middleware can then use the peer certificate to authenticate the client.
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

/// The middleware that checks the peer certificate and extracts the common name.
///
/// This middleware checks and extracts the peer certificate for a common name.
/// The common name is then added to the request context so that it can be used by other middleware or handlers.
pub(crate) struct SslAuth;

impl<S, B> Transform<S, ServiceRequest> for SslAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Transform = SslAuthMiddleware<S>;

    /// Create a new instance of the `SslAuth` middleware.
    fn new_transform(&self, service: S) -> Self::Future {
        debug!("Ssl Authentication enabled");
        // Create a new instance of the `SslAuthMiddleware`.
        ok(SslAuthMiddleware {
            service: Rc::new(service),
        })
    }
}

pub(crate) struct SslAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SslAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;

    /// Poll the `SslAuthMiddleware` for readiness.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        // Poll the underlying service for readiness.
        self.service.poll_ready(ctx)
    }

    /// Call the `SslAuthMiddleware`.
    ///
    /// This function calls the underlying service and checks the peer certificate for a common name.
    /// If the common name is found, it is added to the request context so that it can be used by other middleware or handlers.
    /// If the common name is not found, an unauthorized response is returned.
    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Log that the middleware is being called.
        trace!("Ssl Authentication...");
        let service = self.service.clone();

        Box::pin(async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!(
                    "JWT: An authenticated user was found; there is no need to authenticate \
                     twice..."
                );
            } else {
                match ssl_auth(&req) {
                    Ok(user) => {
                        // Authentication successful, insert the claim into request extensions
                        // and proceed with the request
                        req.extensions_mut().insert(user);
                    }
                    Err(e) => {
                        debug!("Client certificate authentication failed: {e:?}");
                    }
                }
            }
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

fn ssl_auth(req: &ServiceRequest) -> KResult<AuthenticatedUser> {
    // Get the peer certificate from the context of the request.
    let Some(certificate) = req.conn_data::<PeerCertificate>() else {
        // Log that the peer certificate is not present.
        trace!("Ssl Authentication: no peer certificate found");
        return Err(KmsError::InvalidRequest(
            "SSL Authentication: no peer certificate found".to_owned(),
        ))
    };

    // Extract the common name from the peer certificate.
    match certificate
        .cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
    {
        None => kms_bail!("Client certificate has no common name"),
        Some(cn) => match cn.data().as_utf8() {
            Ok(cn) => {
                trace!("Client certificate common name: {}", cn);
                Ok(AuthenticatedUser {
                    username: cn.to_string(),
                })
            }
            Err(e) => kms_bail!("Client certificate common name is not UTF-8: {}", e),
        },
    }
}
