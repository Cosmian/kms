use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
    },
};

pub mod ckm_rsa_aes_key_wrap;
#[cfg(feature = "non-fips")]
pub mod ckm_rsa_pkcs;
pub mod ckm_rsa_pkcs_oaep;
pub mod operation;
pub mod sign;
#[path = "verify.rs"]
pub mod verify;

// Re-export for simpler import paths
pub use sign::sign_rsa_digest_with_algorithm;

#[must_use]
pub fn default_cryptographic_parameters(
    cryptographic_parameters: Option<&CryptographicParameters>,
) -> (
    CryptographicAlgorithm,
    PaddingMethod,
    HashingAlgorithm,
    DigitalSignatureAlgorithm,
) {
    cryptographic_parameters.map_or_else(
        || {
            (
                CryptographicAlgorithm::RSA,
                PaddingMethod::OAEP,
                HashingAlgorithm::SHA256,
                DigitalSignatureAlgorithm::RSASSAPSS,
            )
        },
        |cp| {
            (
                cp.cryptographic_algorithm
                    .unwrap_or(CryptographicAlgorithm::RSA),
                cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
                cp.digital_signature_algorithm
                    .unwrap_or(DigitalSignatureAlgorithm::RSASSAPSS),
            )
        },
    )
}
