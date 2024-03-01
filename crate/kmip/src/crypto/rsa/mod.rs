#[cfg(feature = "fips")]
use crate::kmip::kmip_types::CryptographicUsageMask;

#[cfg(feature = "openssl")]
pub mod ckm_rsa_aes_key_wrap;
#[cfg(feature = "openssl")]
pub mod ckm_rsa_pkcs_oaep;
pub mod kmip_requests;
#[cfg(feature = "openssl")]
pub mod operation;
#[cfg(feature = "openssl")]
pub mod rsa_oaep_aes_gcm;

#[cfg(feature = "fips")]
/// FIPS minimum modulus length in bits.
pub const FIPS_MIN_RSA_MODULUS_LENGTH: u32 = 2048;

#[cfg(feature = "fips")]
/// RSA private key mask usage for FIPS mode: signing, auth and encryption.
pub const FIPS_PRIVATE_RSA_MASK: CryptographicUsageMask = CryptographicUsageMask::Sign
    .union(CryptographicUsageMask::Decrypt)
    .union(CryptographicUsageMask::UnwrapKey)
    .union(CryptographicUsageMask::DeriveKey)
    .union(CryptographicUsageMask::KeyAgreement);

#[cfg(feature = "fips")]
/// ECC public key mask usage for FIPS mode: signing, auth and encryption.
pub const FIPS_PUBLIC_RSA_MASK: CryptographicUsageMask = CryptographicUsageMask::Verify
    .union(CryptographicUsageMask::Encrypt)
    .union(CryptographicUsageMask::WrapKey)
    .union(CryptographicUsageMask::DeriveKey)
    .union(CryptographicUsageMask::KeyAgreement);
