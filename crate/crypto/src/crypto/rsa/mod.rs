use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};

pub mod ckm_rsa_aes_key_wrap;
#[cfg(feature = "non-fips")]
pub mod ckm_rsa_pkcs;
pub mod ckm_rsa_pkcs_oaep;
pub mod operation;

#[must_use]
pub fn default_cryptographic_parameters(
    cryptographic_parameters: Option<&CryptographicParameters>,
) -> (CryptographicAlgorithm, PaddingMethod, HashingAlgorithm) {
    cryptographic_parameters.map_or_else(
        || {
            (
                CryptographicAlgorithm::RSA,
                PaddingMethod::OAEP,
                HashingAlgorithm::SHA256,
            )
        },
        |cp| {
            (
                cp.cryptographic_algorithm
                    .unwrap_or(CryptographicAlgorithm::RSA),
                cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
            )
        },
    )
}
