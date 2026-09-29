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
//! This module provides:
//! - [`apply_extensions`] — appends the RFC-mandated keyUsage extension
//! - [`is_signing_capable`] — returns whether an algorithm can self-sign

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
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

/// Returns `true` if `algo` can produce digital signatures and therefore can
/// self-sign a certificate.
///
/// ML-KEM and hybrid KEM variants are key encapsulation mechanisms — they
/// cannot sign their own TBS certificate. Any `None` or unlisted algorithm
/// returns `false`, causing the caller to require an external signing CA.
pub(super) const fn is_signing_capable(algo: Option<CryptographicAlgorithm>) -> bool {
    matches!(
        algo,
        Some(
            CryptographicAlgorithm::RSA
                | CryptographicAlgorithm::EC
                | CryptographicAlgorithm::ECDSA
                | CryptographicAlgorithm::Ed25519
                | CryptographicAlgorithm::Ed448
                | CryptographicAlgorithm::MLDSA_44
                | CryptographicAlgorithm::MLDSA_65
                | CryptographicAlgorithm::MLDSA_87
                | CryptographicAlgorithm::SLHDSA_SHA2_128s
                | CryptographicAlgorithm::SLHDSA_SHA2_128f
                | CryptographicAlgorithm::SLHDSA_SHA2_192s
                | CryptographicAlgorithm::SLHDSA_SHA2_192f
                | CryptographicAlgorithm::SLHDSA_SHA2_256s
                | CryptographicAlgorithm::SLHDSA_SHA2_256f
                | CryptographicAlgorithm::SLHDSA_SHAKE_128s
                | CryptographicAlgorithm::SLHDSA_SHAKE_128f
                | CryptographicAlgorithm::SLHDSA_SHAKE_192s
                | CryptographicAlgorithm::SLHDSA_SHAKE_192f
                | CryptographicAlgorithm::SLHDSA_SHAKE_256s
                | CryptographicAlgorithm::SLHDSA_SHAKE_256f
        )
    )
}
