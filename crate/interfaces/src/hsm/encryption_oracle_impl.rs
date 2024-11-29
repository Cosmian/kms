//! This module contains the implementation of the `EncryptionOracle` trait for the `Hsm` plugin.
//! The `HsmEncryptionOracle` struct is a wrapper around an `HSM` instance and is responsible for
//! encrypting and decrypting data using the HSM.
//! This blanket implementation "glues" the `Hsm` interface with the `EncryptionOracle` interface.

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    encryption_oracle::EncryptedContent, CryptographicAlgorithm, EncryptionOracle, InterfaceError,
    InterfaceResult, KeyMetadata, KeyType, HSM,
};

pub struct HsmEncryptionOracle {
    hsm: Arc<dyn HSM + Send + Sync>,
}

impl HsmEncryptionOracle {
    pub fn new(hsm: Arc<dyn HSM + Send + Sync>) -> Self {
        HsmEncryptionOracle { hsm }
    }
}

#[async_trait]
impl EncryptionOracle for HsmEncryptionOracle {
    async fn encrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<EncryptedContent> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (slot_id, key_id) = parse_uid(uid)?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            // Determine the default algorithm based on the key type
            match self.hsm.get_key_type(slot_id, &key_id).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(
                        "The key {}type is not known".to_owned(),
                    ))
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => CryptographicAlgorithm::AesGcm,
                    KeyType::RsaPublicKey => CryptographicAlgorithm::RsaOaep,
                    KeyType::RsaPrivateKey => {
                        return Err(InterfaceError::Default(
                            "An RSA private key cannot be used to decrypt".to_owned(),
                        ))
                    }
                },
            }
        };
        self.hsm
            .encrypt(slot_id, &key_id, cryptographic_algorithm, data)
            .await
            .map_err(Into::into)
    }

    async fn decrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        if authenticated_encryption_additional_data.is_some() {
            return Err(InterfaceError::InvalidRequest(
                "Additional authenticated data are not supported on HSMs for now".to_owned(),
            ));
        }
        let (slot_id, key_id) = parse_uid(uid)?;
        let cryptographic_algorithm = if let Some(ca) = cryptographic_algorithm {
            ca
        } else {
            // Determine the default algorithm based on the key type
            match self.hsm.get_key_type(slot_id, &key_id).await? {
                None => {
                    return Err(InterfaceError::InvalidRequest(
                        "The key {}type is not known".to_owned(),
                    ))
                }
                Some(key_type) => match key_type {
                    KeyType::AesKey => CryptographicAlgorithm::AesGcm,
                    KeyType::RsaPrivateKey => CryptographicAlgorithm::RsaOaep,
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
            .map_err(Into::into)
    }

    async fn get_key_type(&self, key_id: &str) -> InterfaceResult<Option<KeyType>> {
        let (slot_id, key_id) = parse_uid(key_id)?;
        self.hsm.get_key_type(slot_id, &key_id).await
    }

    async fn get_key_metadata(&self, key_id: &str) -> InterfaceResult<Option<KeyMetadata>> {
        let (slot_id, key_id) = parse_uid(key_id)?;
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
