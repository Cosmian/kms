//! This module contains the code to generate a self-signed certificate for the server.
//!
//! On Linux: the code will attempt to generate a self-signed RA-TLS certificate.
//! If that fails and `ensure_ra_tls` is set the server will fail starting
//! otherwise it will generate a standard self-signed TLS certificate.
//!
//! On other targets, the code will generate a standard self-signed TLS certificate.
//! If `ensure_ra_tls` is set, the server will fail starting
//! with an error message explaining that RA-TLS is not available for this platform.
//!
//! The choice of making the detection OS-dependent is because RA-TLS is only supported on Linux via the ratls crate.
//! Intel and AMD stopped shipping drivers for other targets.

#[cfg(target_os = "linux")]
mod ra_tls;
mod tls;

use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

use crate::result::KResult;

#[cfg(target_os = "linux")]
pub(crate) fn generate_self_signed_cert(
    subject: &str,
    expiration_days: u64,
    ensure_ra_tls: bool,
) -> KResult<(PKey<Private>, X509)> {
    if ensure_ra_tls {
        ra_tls::generate_self_signed_ra_tls_cert(subject, expiration_days)
    } else {
        ra_tls::generate_self_signed_ra_tls_cert(subject, expiration_days)
            .or(tls::generate_self_signed_tls_cert(subject, expiration_days))
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn generate_self_signed_cert(
    subject: &str,
    expiration_days: u64,
    ensure_ra_tls: bool,
) -> KResult<(PKey<Private>, X509)> {
    use crate::kms_bail;
    if ensure_ra_tls {
        kms_bail!("RA-TLS is not supported on this platform")
    }
    tls::generate_self_signed_tls_cert(subject, expiration_days)
}
