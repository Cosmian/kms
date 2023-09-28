//! This module contains the code to generate a self-signed certificate for the server.
//! It will attempt to generate a RA-TLS certificate if the target OS is Linux.
//! If that fails or if the target OS is not Linux, it will generate a standard TLS certificate.
//!
//! The choice of making the detection OS-dependent is because RA-TLS is only supported on Linux via the ra_tls crate.
//! This is debatable as the availability of enclave technology (SGX, TDX, SEV-SNP) is not OS-dependent.
//! The ra_tls should support generating the self-signed cert on the given technologies (or lack thereof)
//! based on runtime detection of its availability.

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
) -> KResult<(PKey<Private>, X509)> {
    ra_tls::generate_self_signed_ra_tls_cert(subject, expiration_days)
        .or(tls::generate_self_signed_tls_cert(subject, expiration_days))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn generate_self_signed_cert(
    subject: &str,
    expiration_days: u64,
) -> KResult<(PKey<Private>, X509)> {
    tls::generate_self_signed_tls_cert(subject, expiration_days)
}
