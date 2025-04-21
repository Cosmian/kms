use std::fmt::Display;

use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};
use serde::Deserialize;
use strum::EnumString;

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum RsaEncryptionAlgorithm {
    #[cfg(not(feature = "fips"))]
    // a.k.a PKCS#1 v1.5 RSA
    CkmRsaPkcs,
    // a.k.a PKCS#1 RSA OAEP
    CkmRsaPkcsOaep,
    // CKM_RSA_AES_KEY_WRAP
    CkmRsaAesKeyWrap,
}

impl Display for RsaEncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl RsaEncryptionAlgorithm {
    #[must_use]
    pub fn to_cryptographic_parameters(self, hash_fn: HashFn) -> CryptographicParameters {
        match self {
            #[cfg(not(feature = "fips"))]
            Self::CkmRsaPkcs => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::PKCS1v15),
                hashing_algorithm: None,
                ..Default::default()
            },
            Self::CkmRsaPkcsOaep => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::OAEP),
                hashing_algorithm: Some(hash_fn.into()),
                ..Default::default()
            },
            Self::CkmRsaAesKeyWrap => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(hash_fn.into()),
                ..Default::default()
            },
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CkmRsaPkcsOaep => "ckm-rsa-pkcs-oaep",
            Self::CkmRsaAesKeyWrap => "ckm-rsa-aes-key-wrap",
            #[cfg(not(feature = "fips"))]
            Self::CkmRsaPkcs => "ckm-rsa-pkcs",
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum HashFn {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl Display for HashFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha224 => write!(f, "sha224"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha384 => write!(f, "sha384"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Sha3_224 => write!(f, "sha3-224"),
            Self::Sha3_256 => write!(f, "sha3-256"),
            Self::Sha3_384 => write!(f, "sha3-384"),
            Self::Sha3_512 => write!(f, "sha3-512"),
        }
    }
}

impl From<HashFn> for HashingAlgorithm {
    fn from(value: HashFn) -> Self {
        match value {
            HashFn::Sha1 => Self::SHA1,
            HashFn::Sha224 => Self::SHA224,
            HashFn::Sha256 => Self::SHA256,
            HashFn::Sha384 => Self::SHA384,
            HashFn::Sha512 => Self::SHA512,
            HashFn::Sha3_224 => Self::SHA3224,
            HashFn::Sha3_256 => Self::SHA3256,
            HashFn::Sha3_384 => Self::SHA3384,
            HashFn::Sha3_512 => Self::SHA3512,
        }
    }
}
