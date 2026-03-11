//! # Crypto Oracle
//! The crypto oracle interface should be implemented by plugins that provide cryptographic
//! capabilities (encryption, decryption, signing) for a given key prefix.
//! Once implemented, a crypto oracle must be registered on the KMS instance for that prefix.
//! HSMs that implement the `HSM` interface have a blanket implementation of this interface called
//! `HsmCryptoOracle`.
use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
    },
};
use zeroize::Zeroizing;

use crate::{InterfaceError, KeyType, error::InterfaceResult};

#[derive(Debug)]
pub struct KeyMetadata {
    pub key_type: KeyType,
    pub key_length_in_bits: usize,
    pub sensitive: bool,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    AesCbc,
    AesGcm,
    RsaPkcsV15,
    RsaOaepSha256,
    RsaOaepSha1,
}

impl CryptoAlgorithm {
    pub fn from_kmip(value: &CryptographicParameters) -> Result<Option<Self>, InterfaceError> {
        value
            .cryptographic_algorithm
            .map_or(Ok(None), |algorithm| match algorithm {
                cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::AES => value
                    .block_cipher_mode
                    .map_or(
                        Ok(Some(Self::AesGcm)),
                        |block_cipher_mode| match block_cipher_mode {
                            BlockCipherMode::CBC => Ok(Some(Self::AesCbc)),
                            BlockCipherMode::GCM => Ok(Some(Self::AesGcm)),
                            bcm => Err(InterfaceError::Default(format!(
                                "Block cipher mode: {bcm:?} not supported for AES",
                            ))),
                        },
                    ),
                cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::RSA => value
                    .padding_method
                    .map_or(Ok(Some(Self::RsaOaepSha256)), |padding_method| {
                        match padding_method {
                            PaddingMethod::OAEP => match value.hashing_algorithm {
                                Some(HashingAlgorithm::SHA1) => Ok(Some(Self::RsaOaepSha1)),
                                _ => Ok(Some(Self::RsaOaepSha256)), // this is debatable
                            },
                            PaddingMethod::PKCS1v15 => Ok(Some(Self::RsaPkcsV15)),
                            pm => Err(InterfaceError::Default(format!(
                                "Padding method: {pm:?} not supported for RSA",
                            ))),
                        }
                    }),
                x => Err(InterfaceError::Default(format!(
                    "Cryptographic algorithm: {x:?} not supported",
                ))),
            })
    }

    /// Selects a default AES algorithm from the provided list of supported algorithms.
    ///
    /// Preference order:
    /// 1. `AesGcm`
    /// 2. `AesCbc`
    pub fn get_aes_algorithm(supported_algorithms: &[Self]) -> InterfaceResult<Self> {
        if supported_algorithms.contains(&Self::AesGcm) {
            return Ok(Self::AesGcm);
        } else if supported_algorithms.contains(&Self::AesCbc) {
            return Ok(Self::AesCbc);
        }
        Err(InterfaceError::InvalidRequest(
            "AES not supported".to_owned(),
        ))
    }

    /// Selects a default RSA algorithm from the provided list of supported algorithms.
    ///
    /// Preference order:
    /// 1. `RsaOaepSha256`
    /// 2. `RsaOaepSha1`
    /// 3. `RsaPkcsV15`
    pub fn get_rsa_algorithm(supported_algorithms: &[Self]) -> InterfaceResult<Self> {
        if supported_algorithms.contains(&Self::RsaOaepSha256) {
            return Ok(Self::RsaOaepSha256);
        } else if supported_algorithms.contains(&Self::RsaOaepSha1) {
            return Ok(Self::RsaOaepSha1);
        } else if supported_algorithms.contains(&Self::RsaPkcsV15) {
            return Ok(Self::RsaPkcsV15);
        }
        Err(InterfaceError::InvalidRequest(
            "RSA not supported".to_owned(),
        ))
    }
}

/// Signing algorithms supported by the crypto oracle / HSM.
///
/// Each variant maps directly to a PKCS#11 signing mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// `CKM_RSA_PKCS` (raw PKCS#1 v1.5 — caller hashes)
    RsaPkcsV15,
    /// `CKM_SHA1_RSA_PKCS`
    Sha1WithRsa,
    /// `CKM_SHA256_RSA_PKCS`
    Sha256WithRsa,
    /// `CKM_SHA384_RSA_PKCS`
    Sha384WithRsa,
    /// `CKM_SHA512_RSA_PKCS`
    Sha512WithRsa,
}

impl SigningAlgorithm {
    /// Derive a `SigningAlgorithm` from KMIP `CryptographicParameters`.
    ///
    /// Resolution order:
    /// 1. `digital_signature_algorithm` (most explicit)
    /// 2. `cryptographic_algorithm` + `hashing_algorithm`
    /// 3. fallback to `Sha256WithRsa` when only RSA is specified
    pub fn from_kmip(params: Option<&CryptographicParameters>) -> Result<Self, InterfaceError> {
        let Some(params) = params else {
            return Ok(Self::Sha256WithRsa);
        };

        // 1. explicit digital_signature_algorithm
        if let Some(dsa) = &params.digital_signature_algorithm {
            return match dsa {
                DigitalSignatureAlgorithm::SHA1WithRSAEncryption => Ok(Self::Sha1WithRsa),
                DigitalSignatureAlgorithm::SHA224WithRSAEncryption
                | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => Ok(Self::Sha256WithRsa),
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption => Ok(Self::Sha384WithRsa),
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption => Ok(Self::Sha512WithRsa),
                other => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported digital signature algorithm for HSM signing: {other:?}"
                ))),
            };
        }

        // 2. cryptographic_algorithm + hashing_algorithm
        if params.cryptographic_algorithm == Some(CryptographicAlgorithm::RSA) {
            return match params.hashing_algorithm {
                Some(HashingAlgorithm::SHA1) => Ok(Self::Sha1WithRsa),
                Some(HashingAlgorithm::SHA256) | None => Ok(Self::Sha256WithRsa),
                Some(HashingAlgorithm::SHA384) => Ok(Self::Sha384WithRsa),
                Some(HashingAlgorithm::SHA512) => Ok(Self::Sha512WithRsa),
                Some(other) => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for RSA signing: {other:?}"
                ))),
            };
        }

        // Default
        Ok(Self::Sha256WithRsa)
    }
}

#[derive(Debug, Default)]
pub struct EncryptedContent {
    pub ciphertext: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    pub tag: Option<Vec<u8>>,
}

#[async_trait]
pub trait CryptoOracle: Send + Sync {
    /// Encrypt data
    /// # Arguments
    /// * `uid` - the ID of the key to use for encryption.
    /// * `data` - the data to encrypt.
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for encryption.
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated encryption.
    /// # Returns
    /// * `Vec<u8>` - the encrypted data
    async fn encrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<EncryptedContent>;

    /// Decrypt data
    /// # Arguments
    /// * `uid` - the ID of the key to use for decryption.
    /// * `data` - the data to decrypt.
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for decryption.
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated decryption.
    /// # Returns
    /// * `Vec<u8>` - the decrypted data
    async fn decrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<Zeroizing<Vec<u8>>>;

    /// Get the key type
    /// On HSMs, this should be a single call to the HSM.
    /// # Arguments
    /// * `uid` - the ID of the key
    /// # Returns
    /// * `KeyType` - the type of the key
    async fn get_key_type(&self, uid: &str) -> InterfaceResult<Option<KeyType>>;

    /// Get the metadata of a key
    /// On HSMs, this should be a double call to the HSM.
    /// # Arguments
    /// * `uid` - the ID of the key
    /// # Returns
    /// * `KeyMetadata` - the metadata of the key
    async fn get_key_metadata(&self, uid: &str) -> InterfaceResult<Option<KeyMetadata>>;

    /// Sign data using the key identified by `uid`.
    ///
    /// # Arguments
    /// * `uid` - the ID of the private key to use for signing
    /// * `data` - the data (or pre-digested data) to sign
    /// * `cryptographic_parameters` - optional cryptographic parameters (algorithm, padding, …)
    /// # Returns
    /// * `InterfaceResult<Vec<u8>>` - the raw signature bytes
    async fn sign(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_parameters: Option<&CryptographicParameters>,
    ) -> InterfaceResult<Vec<u8>>;
}
