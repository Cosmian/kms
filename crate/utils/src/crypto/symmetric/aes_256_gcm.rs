use std::{convert::TryFrom, sync::Mutex};

use cloudproof::reexport::crypto_core::{
    reexport::{aead::AeadInPlace, rand_core::SeedableRng},
    Aes256Gcm, CsRng, DemInPlace, Nonce,
};
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyBlock,
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
};

use crate::{error::KmipUtilsError, DecryptionSystem, EncryptionSystem};

pub struct AesGcmSystem {
    key_uid: String,
    symmetric_key_key_block: KeyBlock,
    rng: Mutex<CsRng>,
}

impl AesGcmSystem {
    pub fn instantiate(uid: &str, symmetric_key: &Object) -> Result<Self, KmipUtilsError> {
        let key_block = match symmetric_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => {
                return Err(KmipUtilsError::NotSupported(
                    "Expected a KMIP Symmetric Key".to_owned(),
                ))
            }
        };
        Ok(Self {
            key_uid: uid.into(),
            symmetric_key_key_block: key_block,
            rng: Mutex::new(CsRng::from_entropy()),
        })
    }
}

impl EncryptionSystem for AesGcmSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
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
        let key: [u8; Aes256Gcm::KEY_LENGTH] =
            self.symmetric_key_key_block.key_bytes()?.try_into()?;
        let key = SymmetricKey::try_from_bytes(key)?;

        // supplied Nonce or fresh
        let nonce: Nonce<Aes256Gcm::NONCE_LENGTH> = match request.iv_counter_nonce.as_ref() {
            Some(v) => Nonce::try_from(v.as_slice())
                .map_err(|e| KmipUtilsError::NotSupported(e.to_string()))?,
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
        let tag = Aes256Gcm::new(&key)
            .encrypt_in_place_detached(
                &nonce,
                &mut data,
                if ad.is_empty() { None } else { Some(&ad) },
            )
            .map_err(|e| KmipUtilsError::NotSupported(e.to_string()))?;

        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce.as_bytes().to_vec()),
            correlation_value,
            authenticated_encryption_tag: Some(tag),
        })
    }
}

impl DecryptionSystem for AesGcmSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
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
        let key: [u8; Aes256Gcm::KEY_LENGTH] = self
            .symmetric_key_key_block
            .key_bytes()?
            .as_slice()
            .try_into()?;
        let key = SymmetricKey::try_from_bytes(key)?;

        // recover tag
        let tag = request
            .authenticated_encryption_tag
            .clone()
            .unwrap_or_default();

        // recover Nonce
        let nonce_bytes = request.iv_counter_nonce.clone().ok_or_else(|| {
            KmipUtilsError::NotSupported("the nonce is mandatory for AES GCM".to_string())
        })?;
        let nonce: Nonce<{ Aes256Gcm::NONCE_LENGTH }> = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|e| KmipUtilsError::NotSupported(e.to_string()))?;

        // Additional data
        let mut ad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                ad.extend((block_number as usize).to_le_bytes());
            }
        }

        Aes256Gcm::new(&key)
            .decrypt_in_place_detached(
                &nonce,
                &mut bytes,
                &tag,
                if ad.is_empty() { None } else { Some(&ad) },
            )
            .map_err(|e| KmipUtilsError::NotSupported(e.to_string()))?;

        Ok(DecryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(bytes.clone()),
            correlation_value,
        })
    }
}
