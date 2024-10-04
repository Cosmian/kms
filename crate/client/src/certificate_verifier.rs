use std::{sync::Arc, time::SystemTime};

use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, Error as RustTLSError, ServerName,
};

/// A TLS verifier adding the ability to match the leaf certificate with a trusted one.
pub(crate) struct LeafCertificateVerifier {
    // The certificate we expect to see in the TLS connection
    expected_cert: Certificate,
    // A default verifier to run anyway
    default_verifier: Arc<dyn ServerCertVerifier>,
}

impl LeafCertificateVerifier {
    pub(crate) fn new(
        expected_cert: Certificate,
        default_verifier: Arc<dyn ServerCertVerifier>,
    ) -> Self {
        Self {
            expected_cert,
            default_verifier,
        }
    }
}

impl ServerCertVerifier for LeafCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,              // end_entity
        intermediates: &[Certificate],         // intermediates
        server_name: &ServerName,              // server_name
        scts: &mut dyn Iterator<Item = &[u8]>, // scts
        ocsp_response: &[u8],                  // ocsp_response
        now: SystemTime,                       // now
    ) -> Result<ServerCertVerified, RustTLSError> {
        // Verify the leaf certificate
        if !end_entity.eq(&self.expected_cert) {
            return Err(RustTLSError::General(
                "Leaf certificate doesn't match the expected one".to_owned(),
            ))
        }

        // Now proceed with typical verifications
        self.default_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        )
    }
}

/// Remove all verifications
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,                    // end_entity
        _: &[Certificate],                  // intermediates
        _: &ServerName,                     // server_name
        _: &mut dyn Iterator<Item = &[u8]>, // scts
        _: &[u8],                           // ocsp_response
        _: SystemTime,                      // now
    ) -> Result<ServerCertVerified, RustTLSError> {
        Ok(ServerCertVerified::assertion())
    }
}
