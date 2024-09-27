#[cfg(feature = "fips")]
use crate::kmip::kmip_types::CryptographicUsageMask;

#[cfg(not(feature = "fips"))]
pub mod ecies;
pub mod kmip_requests;
pub mod operation;

// Montgomery curves key length.
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
/// ECC private key mask usage for FIPS mode: only signing usage.
pub const FIPS_PRIVATE_ECC_MASK_SIGN: CryptographicUsageMask = CryptographicUsageMask::Sign
    .union(CryptographicUsageMask::CertificateSign)
    .union(CryptographicUsageMask::CRLSign)
    .union(CryptographicUsageMask::Authenticate);

#[cfg(feature = "fips")]
/// ECC public key mask usage for FIPS mode: only signing usage.
pub const FIPS_PUBLIC_ECC_MASK_SIGN: CryptographicUsageMask =
    CryptographicUsageMask::Verify.union(CryptographicUsageMask::Authenticate);

#[cfg(feature = "fips")]
/// ECC private key mask usage for FIPS mode: only key agreement.
pub const FIPS_PRIVATE_ECC_MASK_ECDH: CryptographicUsageMask =
    CryptographicUsageMask::DeriveKey.union(CryptographicUsageMask::KeyAgreement);

#[cfg(feature = "fips")]
/// ECC public key mask usage for FIPS mode: only key agreement.
pub const FIPS_PUBLIC_ECC_MASK_ECDH: CryptographicUsageMask =
    CryptographicUsageMask::DeriveKey.union(CryptographicUsageMask::KeyAgreement);

#[cfg(feature = "fips")]
/// ECC private key mask usage for FIPS mode for curves with signing and key
/// agreement (P curves).
pub const FIPS_PRIVATE_ECC_MASK_SIGN_ECDH: CryptographicUsageMask =
    FIPS_PRIVATE_ECC_MASK_SIGN.union(FIPS_PRIVATE_ECC_MASK_ECDH);

#[cfg(feature = "fips")]
/// ECC public key mask usage for FIPS mode for curves with signing and key
/// agreement (P curves).
pub const FIPS_PUBLIC_ECC_MASK_SIGN_ECDH: CryptographicUsageMask =
    FIPS_PUBLIC_ECC_MASK_SIGN.union(FIPS_PUBLIC_ECC_MASK_ECDH);
