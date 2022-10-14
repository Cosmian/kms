use std::{convert::TryFrom, sync::Mutex};

use cosmian_crypto_base::{
    entropy::CsRng,
    symmetric_crypto::{
        aes_256_gcm_pure::{
            self, decrypt_in_place_detached, encrypt_in_place_detached, Key, Nonce,
        },
        nonce::NonceTrait,
    },
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyBlock,
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
    },
};

mod symmetric_key;
pub use symmetric_key::create_symmetric_key;

#[cfg(test)]
mod tests;

use crate::{DeCipher, EnCipher};

pub struct AesGcmCipher {
    key_uid: String,
    symmetric_key_key_block: KeyBlock,
    rng: Mutex<CsRng>,
}

impl AesGcmCipher {
    pub fn instantiate(uid: &str, symmetric_key: &Object) -> Result<AesGcmCipher, KmipError> {
        let key_block = match symmetric_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Message,
                    "Expected a KMIP Symmetric Key".to_owned(),
                ))
            }
        };
        Ok(AesGcmCipher {
            key_uid: uid.into(),
            symmetric_key_key_block: key_block,
            rng: Mutex::new(CsRng::default()),
        })
    }
}

impl EnCipher for AesGcmCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let uid = request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let correlation_value = request.correlation_value.clone().or_else(|| {
            if uid.is_empty() {
                None
            } else {
                Some(uid.clone())
            }
        });

        let mut data = match &request.data {
            None => {
                return Ok(EncryptResponse {
                    unique_identifier: self.key_uid.clone(),
                    data: None,
                    iv_counter_nonce: None,
                    correlation_value,
                    authenticated_encryption_tag: None,
                })
            }
            Some(data) => data.clone(),
        };

        // recover key
        let key = Key::try_from(self.symmetric_key_key_block.as_bytes()?)
            .map_err(|e| KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        // supplied Nonce or fresh
        let nonce = match request.iv_counter_nonce.as_ref() {
            Some(v) => Nonce::try_from(v.as_slice()).map_err(|e| {
                KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string())
            })?,
            None => {
                let mut rng = self.rng.lock().expect("a mutex lock failed");
                Nonce::new(&mut *rng)
            }
        };

        // Additional data
        let mut ad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                ad.extend((block_number as usize).to_le_bytes());
            }
        }

        // now encrypt
        let tag = encrypt_in_place_detached(
            &key,
            &mut data,
            &nonce,
            if ad.is_empty() { None } else { Some(&ad) },
        )
        .map_err(|e| KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce.into()),
            correlation_value,
            authenticated_encryption_tag: Some(tag),
        })
    }
}

impl DeCipher for AesGcmCipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let uid = request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let correlation_value = if uid.is_empty() {
            None
        } else {
            Some(uid.clone())
        };

        let mut bytes = match &request.data {
            None => {
                return Ok(DecryptResponse {
                    unique_identifier: self.key_uid.clone(),
                    data: None,
                    correlation_value,
                })
            }
            Some(ciphertext) => ciphertext.clone(),
        };

        // recover key
        let key: Key = aes_256_gcm_pure::Key::try_from(self.symmetric_key_key_block.as_bytes()?)
            .map_err(|e| KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        // recover tag
        let tag = request
            .authenticated_encryption_tag
            .clone()
            .unwrap_or_default();

        // recover Nonce
        let nonce_bytes = request.iv_counter_nonce.clone().ok_or_else(|| {
            KmipError::KmipError(
                ErrorReason::Cryptographic_Failure,
                "the nonce is mandatory for AES GCM".to_string(),
            )
        })?;
        let nonce = aes_256_gcm_pure::Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|e| KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        // Additional data
        let mut ad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                ad.extend((block_number as usize).to_le_bytes());
            }
        }

        decrypt_in_place_detached(
            &key,
            &mut bytes,
            &tag,
            &nonce,
            if ad.is_empty() { None } else { Some(&ad) },
        )
        .map_err(|e| KmipError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        Ok(DecryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(bytes.clone()),
            correlation_value,
        })
    }
}
