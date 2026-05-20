//! # RFC 9935 — ML-KEM in X.509 Public Key Infrastructure
//!
//! <https://www.rfc-editor.org/rfc/rfc9935.html>
//!
//! **§5 Key Usage Bits**: Certificates containing ML-KEM public keys MUST include
//! a critical `keyUsage` extension with `keyEncipherment` only. No other key usage
//! bits are permitted.
//!
//! ML-KEM is a key encapsulation mechanism — it cannot produce digital signatures.
//! Therefore ML-KEM certificates **cannot be self-signed** and must always be issued
//! by a signing CA (RSA, EC, ML-DSA, or SLH-DSA).
//!
//! This module provides [`apply_extensions`] which appends the RFC-mandated keyUsage
//! extension to an X.509 certificate being built.

use openssl::x509::{X509Builder, extension::KeyUsage};

use crate::result::KResult;

/// Append the RFC 9935 §5 critical `keyUsage` extension for ML-KEM / hybrid KEM.
///
/// Always `keyEncipherment` only (critical). The `is_ca` parameter is not used
/// because ML-KEM keys cannot be CA keys.
pub(super) fn apply_extensions(x509_builder: &mut X509Builder) -> KResult<()> {
    let ext = KeyUsage::new().critical().key_encipherment().build()?;
    x509_builder.append_extension(ext)?;
    Ok(())
}
