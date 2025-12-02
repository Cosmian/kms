use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::PaddingMethod,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};
use cosmian_kms_client::reexport::cosmian_kms_client_utils::rsa_utils::HashFn;
use serde::Deserialize;
use strum::EnumString;

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum CDigitalSignatureAlgorithm {
    RSASSAPSS,
    ECDSAWithSHA256,
    ECDSAWithSHA384,
    ECDSAWithSHA512,
}

impl CDigitalSignatureAlgorithm {
    #[must_use]
    pub fn to_cryptographic_parameters(self) -> CryptographicParameters {
        match self {
            Self::RSASSAPSS => todo!(),
            Self::ECDSAWithSHA256 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha256.into()),
                ..Default::default()
            },
            Self::ECDSAWithSHA384 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha384.into()),
                ..Default::default()
            },
            Self::ECDSAWithSHA512 => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha512.into()),
                ..Default::default()
            },
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RSASSAPSS => "rsassa-pss",
            Self::ECDSAWithSHA256 => "ecdsa-sha256",
            Self::ECDSAWithSHA384 => "ecdsa-sha384",
            Self::ECDSAWithSHA512 => "ecdsa-sha512",
        }
    }
}
