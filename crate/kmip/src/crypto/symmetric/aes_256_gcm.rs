use openssl::{
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use zeroize::Zeroizing;

use crate::{
    crypto::{DecryptionSystem, EncryptionSystem},
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
        kmip_types::UniqueIdentifier,
    },
    kmip_bail,
};

/// AES 256 GCM key length in bytes.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;
/// AES 256 GCM nonce length in bytes.
pub const AES_256_GCM_IV_LENGTH: usize = 12;
/// AES 256 GCM tag/mac length in bytes.
pub const AES_256_GCM_MAC_LENGTH: usize = 16;

pub struct AesGcmSystem {
    key_uid: String,
    symmetric_key: Zeroizing<Vec<u8>>,
}

impl AesGcmSystem {
    pub fn instantiate(uid: &str, symmetric_key: &Object) -> Result<Self, KmipError> {
        let key_block = match symmetric_key {
            Object::SymmetricKey { key_block } => key_block,
            _ => {
                return Err(KmipError::NotSupported(
                    "Expected a KMIP Symmetric Key".to_owned(),
                ))
            }
        };
        let symmetric_key = key_block.key_bytes()?;

        if symmetric_key.len() != AES_256_GCM_KEY_LENGTH {
            kmip_bail!("Expected a KMIP Symmetric Key of length {AES_256_GCM_KEY_LENGTH}")
        }

        Ok(Self {
            key_uid: uid.into(),
            symmetric_key,
        })
    }
}

impl EncryptionSystem for AesGcmSystem {
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

        let Some(plaintext) = &request.data else {
            return Ok(EncryptResponse {
                unique_identifier: UniqueIdentifier::TextString(self.key_uid.clone()),
                data: None,
                iv_counter_nonce: None,
                correlation_value,
                authenticated_encryption_tag: None,
            })
        };

        // Supplied Nonce or new one.
        let nonce: [u8; AES_256_GCM_IV_LENGTH] = match request.iv_counter_nonce.as_ref() {
            Some(iv) => iv.as_slice().try_into()?,
            None => {
                let mut iv = [0; AES_256_GCM_IV_LENGTH];
                rand_bytes(&mut iv)?;
                iv
            }
        };

        // Additional data.
        let mut aad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base.
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                aad.extend((block_number as usize).to_le_bytes());
            }
        }

        // Create buffer for GCM tag (MAC).
        let mut tag = vec![0; AES_256_GCM_MAC_LENGTH];

        if self.symmetric_key.len() != AES_256_GCM_KEY_LENGTH {
            kmip_bail!("Encrypt: Expected a KMIP Symmetric Key of length {AES_256_GCM_KEY_LENGTH}")
        }

        // Encryption.
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.symmetric_key,
            Some(&nonce),
            &aad,
            plaintext,
            tag.as_mut(),
        )?;

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.key_uid.clone()),
            data: Some(ciphertext),
            iv_counter_nonce: Some(nonce.to_vec()),
            correlation_value,
            authenticated_encryption_tag: Some(tag),
        })
    }
}

impl DecryptionSystem for AesGcmSystem {
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

        let Some(ciphertext) = &request.data else {
            return Ok(DecryptResponse {
                unique_identifier: UniqueIdentifier::TextString(self.key_uid.clone()),
                data: None,
                correlation_value,
            })
        };

        // Recover tag. Ensure it is of correct size.
        let tag: [u8; AES_256_GCM_MAC_LENGTH] = request
            .authenticated_encryption_tag
            .clone()
            .unwrap_or(vec![0_u8; AES_256_GCM_MAC_LENGTH])
            .try_into()?;

        // Recover nonce.
        let request_nonce_bytes = request.iv_counter_nonce.as_ref().ok_or_else(|| {
            KmipError::NotSupported("The nonce is mandatory for AES GCM.".to_string())
        })?;
        let nonce: [u8; AES_256_GCM_IV_LENGTH] = request_nonce_bytes.as_slice().try_into()?;

        // Additional data.
        let mut aad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base.
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                aad.extend((block_number as usize).to_le_bytes());
            }
        }

        if self.symmetric_key.len() != AES_256_GCM_KEY_LENGTH {
            kmip_bail!("Decrypt: Expected a KMIP Symmetric Key of length {AES_256_GCM_KEY_LENGTH}")
        }

        let plaintext = decrypt_aead(
            Cipher::aes_256_gcm(),
            &self.symmetric_key,
            Some(&nonce),
            &aad,
            ciphertext,
            &tag,
        )?;

        Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.key_uid.clone()),
            data: Some(plaintext),
            correlation_value,
        })
    }
}
