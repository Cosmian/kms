use crate::kmip_2_1::kmip_types::CryptographicUsageMask;

/// ECC private key mask usage for FIPS mode: only signing usage.
pub const FIPS_PRIVATE_ECC_MASK_SIGN: CryptographicUsageMask = CryptographicUsageMask::Sign
    .union(CryptographicUsageMask::CertificateSign)
    .union(CryptographicUsageMask::CRLSign)
    .union(CryptographicUsageMask::Authenticate);

/// ECC public key mask usage for FIPS mode: only signing usage.
pub const FIPS_PUBLIC_ECC_MASK_SIGN: CryptographicUsageMask =
    CryptographicUsageMask::Verify.union(CryptographicUsageMask::Authenticate);

/// ECC private key mask usage for FIPS mode: only key agreement.
pub const FIPS_PRIVATE_ECC_MASK_ECDH: CryptographicUsageMask =
    CryptographicUsageMask::DeriveKey.union(CryptographicUsageMask::KeyAgreement);

/// ECC public key mask usage for FIPS mode: only key agreement.
pub const FIPS_PUBLIC_ECC_MASK_ECDH: CryptographicUsageMask =
    CryptographicUsageMask::DeriveKey.union(CryptographicUsageMask::KeyAgreement);

/// ECC private key mask usage for FIPS mode for curves with signing and key
/// agreement (P curves).
pub const FIPS_PRIVATE_ECC_MASK_SIGN_ECDH: CryptographicUsageMask =
    FIPS_PRIVATE_ECC_MASK_SIGN.union(FIPS_PRIVATE_ECC_MASK_ECDH);

/// ECC public key mask usage for FIPS mode for curves with signing and key
/// agreement (P curves).
pub const FIPS_PUBLIC_ECC_MASK_SIGN_ECDH: CryptographicUsageMask =
    FIPS_PUBLIC_ECC_MASK_SIGN.union(FIPS_PUBLIC_ECC_MASK_ECDH);

/// FIPS minimum modulus length in bits.
pub const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 2048;

/// RSA private key mask usage for FIPS mode: signing, auth and encryption.
pub const FIPS_PRIVATE_RSA_MASK: CryptographicUsageMask = CryptographicUsageMask::Sign
    .union(CryptographicUsageMask::Decrypt)
    .union(CryptographicUsageMask::UnwrapKey)
    .union(CryptographicUsageMask::DeriveKey)
    .union(CryptographicUsageMask::KeyAgreement);

/// ECC public key mask usage for FIPS mode: signing, auth and encryption.
pub const FIPS_PUBLIC_RSA_MASK: CryptographicUsageMask = CryptographicUsageMask::Verify
    .union(CryptographicUsageMask::Encrypt)
    .union(CryptographicUsageMask::WrapKey)
    .union(CryptographicUsageMask::DeriveKey)
    .union(CryptographicUsageMask::KeyAgreement);
