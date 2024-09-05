use std::{
    any::Any,
    pin::Pin,
    task::{Context, Poll},
};

use actix_service::{Service, Transform};
use actix_tls::accept::openssl::TlsStream;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{Extensions, ServiceRequest, ServiceResponse},
    rt::net::TcpStream,
    Error, HttpMessage, HttpResponse,
};
use futures::{
    future::{ok, Ready},
    Future,
};
use openssl::{nid::Nid, x509::X509};
use tracing::{debug, error, trace};

use crate::{kms_bail, result::KResult};

// see this https://github.com/actix/actix-web/pull/1754#issuecomment-716192605
// for inspiration

/// The extension struct holding the peer certificate in connect.
///
/// This struct is used to store the peer certificate in the request context.
#[derive(Debug, Clone)]
pub(crate) struct PeerCertificate {
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
        // Get the peer certificate from the TLS connection.
        if let Some(cert) = cnx.ssl().peer_certificate() {
            // Add the peer certificate to the request context.
            extensions.insert(PeerCertificate { cert });
        }
    }
}

/// The extension struct holding the peer common name in the `HttpRequest`.
///
/// This struct is used to store the peer common name in the request context.
#[derive(Debug, Clone)]
pub(crate) struct PeerCommonName {
    /// The peer common name.
    pub(crate) common_name: String,
}

/// The middleware that checks the peer certificate and extracts the common name.
///
/// This middleware checks the peer certificate for a common name and extracts it.
/// The common name is then added to the request context so that it can be used by other middleware or handlers.
pub(crate) struct SslAuth;

impl<S, B> Transform<S, ServiceRequest> for SslAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
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
        ok(SslAuthMiddleware { service })
    }
}

pub(crate) struct SslAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SslAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Error = Error;
    #[allow(clippy::type_complexity)]
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

        // Get the peer certificate from the request context.
        let certificate = req.conn_data::<PeerCertificate>().cloned();

        // Check if the peer certificate is present.
        match certificate {
            None => {
                // Log that the peer certificate is not present.
                error!("{:?} {} Common name not found", req.method(), req.path(),);

                // Create an unauthorized response.
                Box::pin(async move {
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish())
                        .map_into_right_body())
                })
            }
            Some(certificate) => {
                // Extract the common name from the peer certificate.
                let common_name = extract_common_name(&certificate.cert);

                // Check if the common name is valid.
                match common_name {
                    Ok(common_name) => {
                        // Log that the peer certificate is valid.
                        trace!("Ssl access granted to {}!", common_name);

                        // Add the common name to the request context.
                        req.extensions_mut().insert(PeerCommonName { common_name });

                        // Call the underlying service.
                        let fut = self.service.call(req);

                        // Wrap the future in a `Pin` and `Box`.
                        Box::pin(async move {
                            let res = fut.await?;
                            Ok(res.map_into_left_body())
                        })
                    }
                    Err(e) => {
                        // Log that the peer certificate is not valid.
                        error!("{:?} {} {}", req.method(), req.path(), e);

                        // Create an unauthorized response.
                        Box::pin(async move {
                            Ok(req
                                .into_response(HttpResponse::Unauthorized().finish())
                                .map_into_right_body())
                        })
                    }
                }
            }
        }
    }
}

/// Extract the common name from the client certificate
pub(crate) fn extract_common_name(cert: &X509) -> KResult<String> {
    match cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        None => kms_bail!("Client certificate has no common name"),
        Some(cn) => match cn.data().as_utf8() {
            Ok(cn) => {
                trace!("Client certificate common name: {}", cn);
                Ok(cn.to_string())
            }
            Err(e) => kms_bail!("Client certificate common name is not UTF-8: {}", e),
        },
    }
}
