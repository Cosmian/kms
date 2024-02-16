#[cfg(feature = "fips")]
use crate::kmip::kmip_types::CryptographicUsageMask;

#[cfg(not(feature = "fips"))]
pub mod ecies;
pub mod kmip_requests;
pub mod operation;

// Montgomerry curves key length.
pub const X25519_PRIVATE_KEY_LENGTH: usize = 0x20;
pub const X25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const X448_PRIVATE_KEY_LENGTH: usize = 0x38;
pub const X448_PUBLIC_KEY_LENGTH: usize = 0x38;

// Edwards curves key length.
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 0x20;
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const ED448_PRIVATE_KEY_LENGTH: usize = 0x39;
pub const ED448_PUBLIC_KEY_LENGTH: usize = 0x39;

pub const CURVE_25519_Q_LENGTH_BITS: i32 = 253;

#[cfg(feature = "fips")]
/// ECC mask usage for FIPS mode: only signing usage.
pub const FIPS_ECC_USAGE_MASK: CryptographicUsageMask = CryptographicUsageMask::Sign
    .union(CryptographicUsageMask::Verify)
    .union(CryptographicUsageMask::CertificateSign)
    .union(CryptographicUsageMask::CRLSign)
    .union(CryptographicUsageMask::Authenticate);

#[cfg(feature = "fips")]
/// ECC mask usage for FIPS mode for curves with key agreement (P curves).
pub const FIPS_ECC_USAGE_MASK_WITH_DH: CryptographicUsageMask =
    FIPS_ECC_USAGE_MASK.union(CryptographicUsageMask::KeyAgreement);
