#[cfg(feature = "fips")]
use crate::kmip::kmip_types::CryptographicUsageMask;
use crate::kmip::kmip_types::{
    CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm, PaddingMethod,
};

#[cfg(feature = "openssl")]
pub mod ckm_rsa_aes_key_wrap;
#[cfg(feature = "openssl")]
#[cfg(not(feature = "fips"))]
pub mod ckm_rsa_pkcs;
#[cfg(feature = "openssl")]
pub mod ckm_rsa_pkcs_oaep;
pub mod kmip_requests;
#[cfg(feature = "openssl")]
pub mod operation;

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

#[must_use]
pub fn default_cryptographic_parameters(
    cryptographic_parameters: Option<&CryptographicParameters>,
) -> (CryptographicAlgorithm, PaddingMethod, HashingAlgorithm) {
    cryptographic_parameters
        .map(|cp| {
            (
                cp.cryptographic_algorithm
                    .unwrap_or(CryptographicAlgorithm::RSA),
                cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
            )
        })
        .unwrap_or_else(|| {
            (
                // default to CKM_RSA_PKCS_OAEP_KEY_WRAP
                CryptographicAlgorithm::RSA,
                PaddingMethod::OAEP,
                HashingAlgorithm::SHA256,
            )
        })
}
