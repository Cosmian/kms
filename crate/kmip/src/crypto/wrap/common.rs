use crate::kmip::{
    kmip_data_structures::KeyWrappingData,
    kmip_types::{CryptographicAlgorithm, HashingAlgorithm, PaddingMethod},
};

pub(crate) fn rsa_parameters(
    key_wrapping_data: &KeyWrappingData,
) -> (CryptographicAlgorithm, PaddingMethod, HashingAlgorithm) {
    key_wrapping_data
        .encryption_key_information
        .as_ref()
        .and_then(|eki| eki.cryptographic_parameters.as_ref())
        .map_or_else(
            || {
                (
                    CryptographicAlgorithm::AES,
                    PaddingMethod::OAEP,
                    HashingAlgorithm::SHA256,
                )
            },
            |cp| {
                (
                    cp.cryptographic_algorithm
                        .unwrap_or(CryptographicAlgorithm::AES),
                    cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                    cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
                )
            },
        )
}
