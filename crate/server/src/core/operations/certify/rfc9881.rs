//! # RFC 9881 — ML-DSA in X.509 Public Key Infrastructure
//!
//! <https://www.rfc-editor.org/rfc/rfc9881.html>
//!
//! **§5 Key Usage Bits**: Certificates containing ML-DSA public keys MUST include
//! a critical `keyUsage` extension with `digitalSignature`. For CA certificates,
//! `keyCertSign` and `cRLSign` are also permitted (RFC 9881 §5 + RFC 5280 §4.2.1.3).
//!
//! This module provides [`apply_extensions`] which appends the RFC-mandated keyUsage
//! extension to an X.509 certificate being built.

use openssl::x509::X509Builder;

use super::pqc_signing_key_usage;
use crate::result::KResult;

/// Append the RFC 9881 §5 critical `keyUsage` extension for ML-DSA.
///
/// - End-entity: `digitalSignature` (critical)
/// - CA: `digitalSignature | keyCertSign | cRLSign` (critical)
pub(super) fn apply_extensions(x509_builder: &mut X509Builder, is_ca: bool) -> KResult<()> {
    let ext = pqc_signing_key_usage(is_ca)?;
    x509_builder.append_extension(ext)?;
    Ok(())
}
