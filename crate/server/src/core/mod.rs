pub(crate) mod certificate;
pub(crate) mod cover_crypt;
mod kms;
pub(crate) mod operations;
mod retrieve_object_utils;
mod uid_utils;
pub(crate) mod wrapping;

//TODO Once the KMIP crate is refactored to remove the dependency to openssl,
// the `interfaces` crate can depend on KMIP and this function must be moved to the `ìnterfaces` crate

use cosmian_kmip::kmip::kmip_types::{
    BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, PaddingMethod,
};
use cosmian_kms_interfaces::CryptographicAlgorithm as InterfaceCrytpAlg;
pub use kms::KMS;

use crate::{error::KmsError, result::KResult};

pub(crate) fn to_cryptographic_algorithm(
    cp: &CryptographicParameters,
) -> KResult<Option<InterfaceCrytpAlg>> {
    cp.cryptographic_algorithm
        .map_or(Ok(None), |algorithm| match algorithm {
            CryptographicAlgorithm::AES => cp.block_cipher_mode.map_or(
                Ok(Some(InterfaceCrytpAlg::AesGcm)),
                |block_cipher_mode| match block_cipher_mode {
                    BlockCipherMode::GCM => Ok(Some(InterfaceCrytpAlg::AesGcm)),
                    bcm => Err(KmsError::Default(format!(
                        "Block cipher mode: {bcm:?} not supported for AES",
                    ))),
                },
            ),
            CryptographicAlgorithm::RSA => {
                cp.padding_method
                    .map_or(Ok(Some(InterfaceCrytpAlg::RsaOaep)), |padding_method| {
                        match padding_method {
                            PaddingMethod::OAEP => Ok(Some(InterfaceCrytpAlg::RsaOaep)),
                            PaddingMethod::PKCS1v15 => Ok(Some(InterfaceCrytpAlg::RsaPkcsV15)),
                            pm => Err(KmsError::Default(format!(
                                "Padding method: {pm:?} not supported for RSA",
                            ))),
                        }
                    })
            }
            x => Err(KmsError::Default(format!(
                "Cryptographic algorithm: {x:?} not supported",
            ))),
        })
}
