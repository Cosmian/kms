//! This module contains the implementation of the `EncryptionOracle` trait for the `Hsm` plugin.
//! The `HsmEncryptionOracle` struct is a wrapper around an `HSM` instance and is responsible for
//! encrypting and decrypting data using the HSM.
//! This blanket implementation "glues" the `Hsm` interface with the `EncryptionOracle` interface.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    CryptoAlgorithm, EncryptionOracle, HSM, InterfaceError, InterfaceResult, KeyMetadata, KeyType,
    encryption_oracle::EncryptedContent,
};

pub struct HsmEncryptionOracle {
    hsm: Arc<dyn HSM + Send + Sync>,
}

impl HsmEncryptionOracle {
    pub fn new(hsm: Arc<dyn HSM + Send + Sync>) -> Self {
        Self { hsm }
    }
}

#[async_trait]
impl EncryptionOracle for HsmEncryptionOracle {
    async fn encrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<EncryptedContent> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (mut slot_id, mut key_id) = parse_uid(uid)?;
        let supported_algorithms = self.hsm.get_supported_algorithms(slot_id).await?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            debug!("Using default algorithm to encrypt");
            match self.hsm.get_key_type(slot_id, &key_id).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(format!(
                        "The key type of key: {uid}, cannot be determined"
                    )))
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => parse_default_aes_algorithm(&supported_algorithms)?,
                    KeyType::RsaPublicKey => parse_default_rsa_algorithm(&supported_algorithms)?,
                    KeyType::RsaPrivateKey => {
                        // try fetching the corresponding public key
                        let pk_uid = format!("{uid}_pk");
                        debug!(
                            "encrypt: an RSA private key {uid} was specified. Trying to use \
                             public key {pk_uid} for encryption"
                        );
                        (slot_id, key_id) = parse_uid(&pk_uid)?;
                        self.hsm
                            .get_key_type(slot_id, &key_id)
                            .await?
                            .ok_or_else(|| {
                                InterfaceError::InvalidRequest(format!(
                                    "The key {uid} is a private key, but no public key {pk_uid} \
                                     is available"
                                ))
                            })?;
                        parse_default_rsa_algorithm(&supported_algorithms)?
                    }
                },
            }
        };
        self.hsm
            .encrypt(slot_id, &key_id, cryptographic_algorithm, data)
            .await
    }

    async fn decrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (slot_id, key_id) = parse_uid(uid)?;
        let supported_algorithms = self.hsm.get_supported_algorithms(slot_id).await?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            debug!("Using default algorithm to decrypt");
            match self.hsm.get_key_type(slot_id, &key_id).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(
                        "The key {}type is not known".to_owned(),
                    ))
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => parse_default_aes_algorithm(&supported_algorithms)?,
                    KeyType::RsaPrivateKey => parse_default_rsa_algorithm(&supported_algorithms)?,
                    KeyType::RsaPublicKey => {
                        return Err(InterfaceError::Default(
                            "An RSA public key cannot be used to decrypt".to_owned(),
                        ))
                    }
                },
            }
        };
        self.hsm
            .decrypt(slot_id, &key_id, cryptographic_algorithm, data)
            .await
    }

    async fn get_key_type(&self, uid: &str) -> InterfaceResult<Option<KeyType>> {
        let (slot_id, key_id) = parse_uid(uid)?;
        self.hsm.get_key_type(slot_id, &key_id).await
    }

    async fn get_key_metadata(&self, uid: &str) -> InterfaceResult<Option<KeyMetadata>> {
        let (slot_id, key_id) = parse_uid(uid)?;
        self.hsm.get_key_metadata(slot_id, &key_id).await
    }
}

/// Parse the `uid` into a `slot_id` and `key_id`
fn parse_uid(uid: &str) -> InterfaceResult<(usize, Vec<u8>)> {
    let (slot_id, key_id) = uid
        .trim_start_matches("hsm::")
        .split_once("::")
        .ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_owned(),
            )
        })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        InterfaceError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    Ok((slot_id, key_id.as_bytes().to_vec()))
}

/// Selects a default AES algorithm from the provided list of supported algorithms.
///
/// Preference order:
/// 1. `AesGcm`
/// 2. `AesCbc`
fn parse_default_aes_algorithm(
    supported_algorithms: &[CryptoAlgorithm],
) -> InterfaceResult<CryptoAlgorithm> {
    if supported_algorithms.contains(&CryptoAlgorithm::AesGcm) {
        return Ok(CryptoAlgorithm::AesGcm);
    } else if supported_algorithms.contains(&CryptoAlgorithm::AesCbc) {
        return Ok(CryptoAlgorithm::AesCbc);
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
fn parse_default_rsa_algorithm(
    supported_algorithms: &[CryptoAlgorithm],
) -> InterfaceResult<CryptoAlgorithm> {
    if supported_algorithms.contains(&CryptoAlgorithm::RsaOaepSha256) {
        return Ok(CryptoAlgorithm::RsaOaepSha256);
    } else if supported_algorithms.contains(&CryptoAlgorithm::RsaOaepSha1) {
        return Ok(CryptoAlgorithm::RsaOaepSha1);
    } else if supported_algorithms.contains(&CryptoAlgorithm::RsaPkcsV15) {
        return Ok(CryptoAlgorithm::RsaPkcsV15);
    }
    Err(InterfaceError::InvalidRequest(
        "RSA not supported".to_owned(),
    ))
}
